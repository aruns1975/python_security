# Security Testing Reference

Every security change ships with tests. The suites below are the reference (`templates/tests/`)
and cover every requirement in the architecture: provider success/failure, concurrency
isolation, context cleanup, 401/403 mapping, interceptor selection, credential isolation,
OAuth2 caching and concurrent refresh, redirect and destination security.

## 1. Setup

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
```

Techniques:
- **Inbound**: `httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")`.
  Generate an RSA key pair per session and mint JWTs with PyJWT — never hit a real IdP.
- **Outbound**: `httpx.MockTransport(handler)` injected into the shared `httpx.AsyncClient`; the
  handler records every request so tests can assert on headers, hosts, and call counts.
- **Service layer**: `with SecurityContextHolder.use(SecurityContext(principal)):` — no HTTP needed.
- Use a cheap scrypt cost (`n=2**10`) in tests only.

## 2. Fixtures

```python
import time
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://idp.example.com/"
AUDIENCE = "orders-api"


@pytest.fixture(scope="session")
def rsa_keys() -> tuple[Any, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_pem


@pytest.fixture
def make_token(rsa_keys: tuple[Any, bytes]) -> Callable[..., str]:
    private_key, _ = rsa_keys

    def _make(sub: str = "user-1", *, scope: str = "ORDER_READ", roles: list[str] | None = None,
              exp_offset: int = 300, **overrides: Any) -> str:
        now = int(time.time())
        claims = {"sub": sub, "iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + exp_offset,
                  "scope": scope, "roles": roles or []}
        claims.update(overrides)
        return jwt.encode(claims, private_key, algorithm="RS256")

    return _make
```

## 3. Inbound tests

```python
import asyncio
import base64

import httpx
import jwt
import pytest
from fastapi import BackgroundTasks, Depends, FastAPI

from security.exceptions import AuthenticationException, AuthorizationException
from security.inbound.api_key_provider import ApiKeyAuthenticationProvider, ApiKeyRecord, InMemoryApiKeyStore, hash_api_key
from security.inbound.basic_auth_provider import BasicAuthenticationProvider, ScryptPasswordHasher, UserRecord
from security.inbound.context_holder import SecurityContextHolder, create_detached_task
from security.inbound.decorators import post_authorize, pre_authorize, secured
from security.inbound.dependencies import CurrentPrincipal, require, require_authority
from security.inbound.jwt_provider import JwtAuthenticationProvider, JwtSettings
from security.inbound.policies import has_authority, has_role
from security.inbound.principal import SecurityContext, SecurityPrincipal
from security.configuration import configure_inbound_security
from tests.conftest import AUDIENCE, ISSUER

PEPPER = b"p" * 32
API_KEY = "sk_live_0123456789abcdef"
SEEN: list = []


class _Users:
    def __init__(self, hasher: ScryptPasswordHasher) -> None:
        self._users = {"alice": UserRecord("alice", hasher.hash("s3cret"), "u-alice", roles=frozenset({"ADMIN"}))}

    async def find_by_username(self, username: str) -> UserRecord | None:
        return self._users.get(username)


@pytest.fixture
def app(rsa_keys) -> FastAPI:
    _, public_pem = rsa_keys
    hasher = ScryptPasswordHasher(n=2**10)
    providers = [
        JwtAuthenticationProvider(JwtSettings(issuer=ISSUER, audience=AUDIENCE, static_key=public_pem)),
        ApiKeyAuthenticationProvider(
            InMemoryApiKeyStore([ApiKeyRecord("k1", hash_api_key(API_KEY, PEPPER), "svc-reporting",
                                              authorities=frozenset({"ORDER_READ"}))]),
            PEPPER,
        ),
        BasicAuthenticationProvider(_Users(hasher), hasher),
    ]
    app = FastAPI()
    configure_inbound_security(app, providers, public_paths=["/health", "/public/"])

    @app.get("/health")
    async def health(): return {"principal": getattr(SecurityContextHolder.get_principal(), "subject", None)}

    @app.get("/me")
    async def me(principal: CurrentPrincipal):
        await asyncio.sleep(0.01)  # force interleaving between concurrent requests
        assert SecurityContextHolder.get_principal() is principal
        return {"subject": principal.subject, "type": principal.authentication_type}

    @app.get("/orders", dependencies=[Depends(require_authority("ORDER_READ"))])
    async def orders(): return []

    @app.delete("/orders/1", dependencies=[Depends(require(has_role("ADMIN")))])
    async def delete_order(): return {"deleted": True}

    @app.get("/sync-me")
    def sync_me():  # sync endpoints run in a threadpool; context must still propagate
        return {"subject": SecurityContextHolder.require_principal().subject}

    @app.get("/bg")
    async def bg(tasks: BackgroundTasks):
        tasks.add_task(lambda: SEEN.append(SecurityContextHolder.get_principal()))
        return {}

    @app.get("/boom")
    async def boom(): raise RuntimeError("boom")

    return app


@pytest.fixture
async def client(app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                 base_url="http://test") as c:
        yield c


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_public_path_allows_anonymous(client):
    r = await client.get("/health")
    assert r.status_code == 200 and r.json() == {"principal": None}


async def test_missing_credentials_401_with_challenge(client):
    r = await client.get("/me")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


async def test_valid_jwt(client, make_token):
    r = await client.get("/me", headers=bearer(make_token("user-9")))
    assert r.json() == {"subject": "user-9", "type": "JWT"}


@pytest.mark.parametrize("overrides", [
    {"exp_offset": -120},
    {"aud": "other-api"},
    {"iss": "https://evil.example.com/"},
])
async def test_invalid_jwt_rejected(client, make_token, overrides):
    r = await client.get("/me", headers=bearer(make_token(**overrides)))
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid or expired token"  # no reason leaked to the client


async def test_unsigned_and_hs256_confusion_tokens_rejected(client, rsa_keys, make_token):
    _, public_pem = rsa_keys
    claims = jwt.decode(make_token(), options={"verify_signature": False})
    none_token = jwt.encode(claims, None, algorithm="none")
    assert (await client.get("/me", headers=bearer(none_token))).status_code == 401
    # Header forged as HS256 using the public key as the HMAC secret.
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    body = make_token().split(".")[1]
    import hashlib, hmac
    sig = base64.urlsafe_b64encode(hmac.new(public_pem, f"{header}.{body}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert (await client.get("/me", headers=bearer(f"{header}.{body}.{sig}"))).status_code == 401


async def test_invalid_token_rejected_even_on_public_path(client):
    assert (await client.get("/health", headers=bearer("garbage"))).status_code == 401


async def test_missing_required_claim_rejected(client, rsa_keys):
    private_key, _ = rsa_keys
    token = jwt.encode({"sub": "x", "iss": ISSUER, "aud": AUDIENCE}, private_key, algorithm="RS256")
    assert (await client.get("/me", headers=bearer(token))).status_code == 401


async def test_api_key(client):
    assert (await client.get("/orders", headers={"X-API-Key": API_KEY})).status_code == 200
    assert (await client.get("/orders", headers={"X-API-Key": "wrong"})).status_code == 401


async def test_basic_auth(client):
    good = base64.b64encode(b"alice:s3cret").decode()
    bad = base64.b64encode(b"alice:nope").decode()
    unknown = base64.b64encode(b"mallory:s3cret").decode()
    assert (await client.get("/me", headers={"Authorization": f"Basic {good}"})).json()["type"] == "BASIC"
    for creds in (bad, unknown, "%%%notbase64"):
        r = await client.get("/me", headers={"Authorization": f"Basic {creds}"})
        assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Basic")


async def test_ambiguous_credentials_rejected(client, make_token):
    r = await client.get("/me", headers={**bearer(make_token()), "X-API-Key": API_KEY})
    assert r.status_code == 401 and "Ambiguous" in r.json()["detail"]


async def test_authorization_403(client, make_token):
    assert (await client.get("/orders", headers=bearer(make_token(scope="OTHER")))).status_code == 403
    assert (await client.delete("/orders/1", headers=bearer(make_token(roles=["USER"])))).status_code == 403
    assert (await client.delete("/orders/1", headers=bearer(make_token(roles=["ADMIN"])))).status_code == 200


async def test_concurrent_requests_keep_their_own_principal(client, make_token):
    subjects = [f"user-{i}" for i in range(50)]
    responses = await asyncio.gather(*(client.get("/me", headers=bearer(make_token(s))) for s in subjects))
    assert [r.json()["subject"] for r in responses] == subjects


async def test_context_reset_after_exception(client, make_token):
    r = await client.get("/boom", headers=bearer(make_token()))
    assert r.status_code == 500
    assert SecurityContextHolder.get_context() is None


# ---- decorators (service layer) ----

ADMIN = SecurityPrincipal("u1", "TEST", authorities={"ORDER_READ"}, roles={"ADMIN"})
USER = SecurityPrincipal("u2", "TEST", authorities=set(), roles={"USER"})


class OrderService:
    @pre_authorize(has_authority("ORDER_READ"))
    async def get_orders(self): return ["o1"]

    @secured("ADMIN")
    def delete(self): return True

    @post_authorize(lambda principal, order: order["owner"] == principal.subject)
    async def get_order(self, owner: str): return {"owner": owner}


async def test_pre_authorize_and_secured():
    svc = OrderService()
    with pytest.raises(AuthenticationException):
        await svc.get_orders()
    with SecurityContextHolder.use(SecurityContext(ADMIN)):
        assert await svc.get_orders() == ["o1"] and svc.delete() is True
    with SecurityContextHolder.use(SecurityContext(USER)):
        with pytest.raises(AuthorizationException):
            await svc.get_orders()
        with pytest.raises(AuthorizationException):
            svc.delete()


async def test_post_authorize():
    svc = OrderService()
    with SecurityContextHolder.use(SecurityContext(ADMIN)):
        assert await svc.get_order("u1") == {"owner": "u1"}
        with pytest.raises(AuthorizationException):
            await svc.get_order("someone-else")


async def test_policy_composition():
    policy = has_role("ADMIN") | has_authority("ORDER_DELETE")
    assert policy(ADMIN) and not policy(USER) and (~policy)(USER)


def test_decorators_reject_generators():
    with pytest.raises(TypeError):
        @pre_authorize(has_role("ADMIN"))
        async def stream():
            yield 1


async def test_detached_task_does_not_inherit_identity():
    async def who(): return SecurityContextHolder.get_principal()
    with SecurityContextHolder.use(SecurityContext(ADMIN)):
        assert await asyncio.create_task(who()) is ADMIN
        assert await create_detached_task(who()) is None
        assert await asyncio.to_thread(SecurityContextHolder.get_principal) is ADMIN


def test_principal_is_immutable():
    claims = {"a": 1}
    p = SecurityPrincipal("s", "T", claims=claims)
    claims["a"] = 2
    assert p.claims["a"] == 1
    with pytest.raises(TypeError):
        p.claims["a"] = 3  # type: ignore[index]
    with pytest.raises(AttributeError):
        p.subject = "x"  # type: ignore[misc]
    assert hash(p)


def test_jwt_settings_guardrails():
    with pytest.raises(ValueError):
        JwtSettings(issuer=ISSUER, audience=AUDIENCE, algorithms=("none",), static_key="k")
    with pytest.raises(ValueError):
        JwtSettings(issuer=ISSUER, audience=AUDIENCE, algorithms=("RS256", "HS256"), static_key="k")
    with pytest.raises(ValueError):
        JwtSettings(issuer=ISSUER, audience=AUDIENCE, jwks_url="http://idp/jwks")


async def test_sync_endpoint_and_background_task_see_identity(client, make_token):
    assert (await client.get("/sync-me", headers=bearer(make_token("u-sync")))).json() == {"subject": "u-sync"}
    SEEN.clear()
    await client.get("/bg", headers=bearer(make_token("u-bg")))
    # BackgroundTasks run inside the request context: they DO act as the caller.
    assert SEEN[0].subject == "u-bg"


async def test_credentials_never_logged(client, make_token, caplog):
    caplog.set_level("DEBUG")
    token = make_token()
    await client.get("/me", headers=bearer(token))
    await client.get("/me", headers=bearer(token + "x"))
    await client.get("/orders", headers={"X-API-Key": API_KEY})
    await client.get("/orders", headers={"X-API-Key": API_KEY + "x"})
    assert token not in caplog.text and API_KEY not in caplog.text
```

## 4. Outbound tests

```python
import asyncio
import base64
import json

import httpx
import pytest

from security.exceptions import OutboundSecurityException, OutboundServiceError
from security.inbound.context_holder import SecurityContextHolder
from security.outbound.interceptor_manager import InterceptorManager
from security.outbound.interceptors.api_key import ApiKeyInterceptor
from security.outbound.interceptors.base import AuthenticationInterceptor
from security.outbound.interceptors.basic_auth import BasicAuthInterceptor
from security.outbound.interceptors.correlation_id import CorrelationIdInterceptor, correlation_id_var
from security.outbound.interceptors.oauth2 import OAuth2Interceptor
from security.outbound.secure_http_client import SecureHttpClient
from security.outbound.service_client import ServiceClient
from security.outbound.service_registry import AuthType, ServiceConfig, ServiceRegistry
from security.outbound.token_provider import ClientCredentialsTokenProvider

SECRETS = {
    ("svc-a", "api_key"): "key-A",
    ("svc-b", "username"): "bob", ("svc-b", "password"): "pw-B",
    ("svc-c", "client_id"): "cid", ("svc-c", "client_secret"): "csecret",
}


class FakeSecrets:
    async def get_secret(self, reference: str, key: str) -> str:
        return SECRETS[(reference, key)]


SERVICES = {
    "A": ServiceConfig(service_id="A", base_url="https://a.example.com/api", auth_type=AuthType.API_KEY, credential_ref="svc-a"),
    "B": ServiceConfig(service_id="B", base_url="https://b.example.com", auth_type=AuthType.BASIC, credential_ref="svc-b"),
    "C": ServiceConfig(service_id="C", base_url="https://c.example.com", auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
                       credential_ref="svc-c", token_url="https://idp.example.com/token", scopes=("stock.read",)),
    "OPEN": ServiceConfig(service_id="OPEN", base_url="https://open.example.com", auth_type=AuthType.NONE),
}


class Downstream:
    """Fake network: records requests, serves a token endpoint and downstream APIs."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.token_calls = 0
        self.responses: dict[str, list[httpx.Response]] = {}

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "idp.example.com":
            self.token_calls += 1
            await asyncio.sleep(0.01)
            return httpx.Response(200, json={"access_token": f"tok-{self.token_calls}", "token_type": "Bearer", "expires_in": 3600})
        queued = self.responses.get(request.url.path)
        if queued:
            return queued.pop(0)
        return httpx.Response(200, json={"ok": True})


@pytest.fixture
def downstream() -> Downstream:
    return Downstream()


@pytest.fixture
async def stack(downstream):
    async with httpx.AsyncClient(transport=httpx.MockTransport(downstream), follow_redirects=False) as http:
        secrets = FakeSecrets()
        manager = InterceptorManager(
            interceptors=[CorrelationIdInterceptor()],
            auth_interceptors=[ApiKeyInterceptor(secrets), BasicAuthInterceptor(secrets),
                               OAuth2Interceptor(ClientCredentialsTokenProvider(http, secrets))],
        )
        yield SecureHttpClient(http, ServiceRegistry(SERVICES), manager, backoff_base_seconds=0)


async def test_api_key_applied_and_base_path_kept(stack, downstream):
    await ServiceClient(stack, "A").get("/v1/invoices", params={"page": 2})
    req = downstream.requests[-1]
    assert str(req.url) == "https://a.example.com/api/v1/invoices?page=2"
    assert req.headers["X-API-Key"] == "key-A" and "authorization" not in req.headers


async def test_basic_auth_applied(stack, downstream):
    await ServiceClient(stack, "B").post("/v1/stock", json={"sku": 1})
    assert downstream.requests[-1].headers["Authorization"] == "Basic " + base64.b64encode(b"bob:pw-B").decode()


async def test_credentials_isolated_between_services(stack, downstream):
    await ServiceClient(stack, "OPEN").get("/x")
    req = downstream.requests[-1]
    assert "authorization" not in req.headers and "x-api-key" not in req.headers


async def test_oauth2_token_cached_and_refreshed_once_concurrently(stack, downstream):
    client = ServiceClient(stack, "C")
    await asyncio.gather(*(client.get("/v1/stock") for _ in range(20)))
    assert downstream.token_calls == 1
    token_req = next(r for r in downstream.requests if r.url.host == "idp.example.com")
    assert b"grant_type=client_credentials" in token_req.content and b"scope=stock.read" in token_req.content
    assert all(r.headers["Authorization"] == "Bearer tok-1" for r in downstream.requests if r.url.host == "c.example.com")


async def test_oauth2_401_refreshes_token_and_retries_once(stack, downstream):
    downstream.responses["/v1/stock"] = [httpx.Response(401), httpx.Response(200, json={"ok": 1})]
    r = await ServiceClient(stack, "C").get("/v1/stock")
    assert r.status_code == 200 and downstream.token_calls == 2
    assert downstream.requests[-1].headers["Authorization"] == "Bearer tok-2"


async def test_persistent_401_raises(stack, downstream):
    downstream.responses["/v1/stock"] = [httpx.Response(401), httpx.Response(401)]
    with pytest.raises(OutboundServiceError) as exc:
        await ServiceClient(stack, "C").get("/v1/stock")
    assert exc.value.status_code == 401


@pytest.mark.parametrize("path", [
    "https://evil.example.com/x", "//evil.example.com/x", "/../admin", "/a/./b", "relative",
    "/x?token=1", "/x#frag", "\\evil",
])
async def test_destination_cannot_escape_registered_origin(stack, downstream, path):
    with pytest.raises(OutboundSecurityException):
        await ServiceClient(stack, "A").get(path)
    assert downstream.requests == []


async def test_redirects_not_followed(stack, downstream):
    downstream.responses["/api/r"] = [httpx.Response(302, headers={"Location": "https://evil.example.com/steal"})]
    with pytest.raises(OutboundServiceError) as exc:
        await ServiceClient(stack, "A").get("/r")
    assert exc.value.status_code == 302
    assert all(r.url.host != "evil.example.com" for r in downstream.requests)


@pytest.mark.parametrize("header", ["Authorization", "x-api-key", "Cookie"])
async def test_caller_cannot_set_credential_headers(stack, header):
    with pytest.raises(OutboundSecurityException):
        await ServiceClient(stack, "A").get("/x", headers={header: "forged"})


async def test_retries_only_idempotent(stack, downstream):
    downstream.responses["/api/get"] = [httpx.Response(503), httpx.Response(200)]
    assert (await ServiceClient(stack, "A").get("/get")).status_code == 200

    downstream.responses["/api/post"] = [httpx.Response(503), httpx.Response(200)]
    with pytest.raises(OutboundServiceError):
        await ServiceClient(stack, "A").post("/post", json={})

    downstream.responses["/api/post2"] = [httpx.Response(503), httpx.Response(200)]
    r = await ServiceClient(stack, "A").post("/post2", json={}, headers={"Idempotency-Key": "abc"})
    assert r.status_code == 200


async def test_error_message_has_no_query_or_secrets(stack, downstream):
    downstream.responses["/api/v1/x"] = [httpx.Response(400, json={"echo": "key-A"})]
    with pytest.raises(OutboundServiceError) as exc:
        await ServiceClient(stack, "A").get("/v1/x", params={"token": "s3cr3t"})
    assert "s3cr3t" not in str(exc.value) and "key-A" not in str(exc.value)


async def test_correlation_id_propagated(stack, downstream):
    token = correlation_id_var.set("corr-123")
    try:
        await ServiceClient(stack, "OPEN").get("/x")
    finally:
        correlation_id_var.reset(token)
    assert downstream.requests[-1].headers["X-Correlation-ID"] == "corr-123"


def test_unknown_service_rejected(stack):
    with pytest.raises(OutboundSecurityException):
        asyncio.run(stack.request("NOPE", "GET", "/x"))


@pytest.mark.parametrize("kwargs", [
    {"base_url": "http://a.example.com", "auth_type": AuthType.NONE},
    {"base_url": "http://a.example.com", "auth_type": AuthType.NONE, "allow_insecure_http": True},
    {"base_url": "https://user:pw@a.example.com", "auth_type": AuthType.NONE},
    {"base_url": "https://a.example.com", "auth_type": AuthType.API_KEY},
    {"base_url": "https://a.example.com", "auth_type": AuthType.OAUTH2_CLIENT_CREDENTIALS, "credential_ref": "r",
     "token_url": "http://idp/token"},
])
def test_service_config_guardrails(kwargs):
    with pytest.raises(ValueError):
        ServiceConfig(service_id="X", **kwargs)


def test_missing_or_duplicate_auth_strategy_fails_fast():
    with pytest.raises(OutboundSecurityException):
        InterceptorManager(auth_interceptors=[ApiKeyInterceptor(FakeSecrets()), ApiKeyInterceptor(FakeSecrets())])
    with pytest.raises(OutboundSecurityException):
        InterceptorManager().validate(ServiceRegistry(SERVICES))


def test_insecure_http_allowed_only_for_loopback():
    for host in ("127.0.0.1", "localhost", "[::1]"):
        ServiceConfig(service_id="L", base_url=f"http://{host}:8080", auth_type=AuthType.NONE, allow_insecure_http=True)


async def test_shared_client_never_stores_or_sends_cookies():
    from security.configuration import OutboundSettings, outbound_security

    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("cookie"))
        return httpx.Response(200, headers={"Set-Cookie": "session=from-a; Path=/"})

    settings = OutboundSettings(services={"A": SERVICES["A"], "OPEN": SERVICES["OPEN"]})
    async with outbound_security(settings, secrets=FakeSecrets(), transport=httpx.MockTransport(handler)) as outbound:
        await outbound.client_for("A").get("/x")
        await outbound.client_for("OPEN").get("/y")
        await outbound.client_for("A").get("/z")
        assert len(outbound.http_client.cookies.jar) == 0
    assert seen == [None, None, None]
```

## 5. Minimum test matrix for any new security code

| Change | Must test |
|---|---|
| New auth provider | valid → principal fields; invalid → 401 + correct `WWW-Authenticate`; missing → anonymous; combined with another credential → ambiguous 401 |
| New protected endpoint | anonymous 401, wrong authority 403, correct authority 2xx, other tenant's resource 404/403 |
| New service method with `@pre_authorize` | no context → `AuthenticationException`; denied → `AuthorizationException`; allowed → result |
| New downstream service | correct credential header present, other services' credentials absent, path escape rejected, no cookies replayed |
| New auth interceptor | header applied, `on_unauthorized` behaviour, missing secret fails clearly without leaking values |
| Token logic | cached across calls, single fetch under `asyncio.gather`, refresh on expiry (inject `clock`), invalidate-on-401 |

Also assert negative logging properties where it matters: capture logs with `caplog` and assert
tokens/keys/passwords never appear.
