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
