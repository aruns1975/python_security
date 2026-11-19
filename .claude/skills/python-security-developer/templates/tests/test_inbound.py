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
