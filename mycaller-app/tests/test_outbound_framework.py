"""Outbound framework tests adapted from the reference suite (testing.md §4), extended for
the new APP_CREDENTIALS auth type and its reserved headers."""

import asyncio

import httpx
import pytest

from main import validate_outbound_settings
from security.configuration import OutboundSettings, outbound_security, verify_outbound_secrets
from security.exceptions import OutboundSecurityException, OutboundServiceError
from security.outbound.credential_provider import EnvSecretStore
from security.outbound.interceptor_manager import InterceptorManager
from security.outbound.interceptors.api_key import ApiKeyInterceptor
from security.outbound.interceptors.app_credentials import AppCredentialsInterceptor
from security.outbound.interceptors.correlation_id import CorrelationIdInterceptor, correlation_id_var
from security.outbound.secure_http_client import SecureHttpClient
from security.outbound.service_client import ServiceClient
from security.outbound.service_registry import AuthType, ServiceConfig, ServiceRegistry

SECRETS = {
    ("svc-a", "api_key"): "key-A",
    ("svc-d", "application_id"): "app-D",
    ("svc-d", "secret_key"): "secret-D",
}


class FakeSecrets:
    async def get_secret(self, reference: str, key: str) -> str:
        return SECRETS[(reference, key)]


SERVICES = {
    "A": ServiceConfig(
        service_id="A", base_url="https://a.example.com/api", auth_type=AuthType.API_KEY, credential_ref="svc-a"
    ),
    "D": ServiceConfig(
        service_id="D", base_url="https://d.example.com", auth_type=AuthType.APP_CREDENTIALS, credential_ref="svc-d"
    ),
    "LOCAL": ServiceConfig(
        service_id="LOCAL",
        base_url="http://127.0.0.1:48081",
        auth_type=AuthType.API_KEY,
        credential_ref="svc-a",
        allow_insecure_http=True,  # local development only
    ),
    "OPEN": ServiceConfig(service_id="OPEN", base_url="https://open.example.com", auth_type=AuthType.NONE),
}


class Downstream:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.responses: dict[str, list[httpx.Response]] = {}

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        queued = self.responses.get(request.url.path)
        if queued:
            return queued.pop(0)
        return httpx.Response(200, json={"ok": True})


@pytest.fixture
def downstream() -> Downstream:
    return Downstream()


@pytest.fixture
async def stack(downstream: Downstream):
    async with httpx.AsyncClient(transport=httpx.MockTransport(downstream), follow_redirects=False) as http:
        secrets = FakeSecrets()
        manager = InterceptorManager(
            interceptors=[CorrelationIdInterceptor()],
            auth_interceptors=[ApiKeyInterceptor(secrets), AppCredentialsInterceptor(secrets)],
        )
        yield SecureHttpClient(http, ServiceRegistry(SERVICES), manager, backoff_base_seconds=0)


async def test_api_key_applied_and_base_path_kept(stack, downstream) -> None:
    await ServiceClient(stack, "A").get("/v1/invoices", params={"page": 2})
    req = downstream.requests[-1]
    assert str(req.url) == "https://a.example.com/api/v1/invoices?page=2"
    assert req.headers["X-API-Key"] == "key-A"
    assert "x-application-id" not in req.headers and "x-secret-key" not in req.headers


async def test_app_credentials_applied(stack, downstream) -> None:
    await ServiceClient(stack, "D").get("/v1/stock")
    req = downstream.requests[-1]
    assert req.headers["X-Application-Id"] == "app-D" and req.headers["X-Secret-Key"] == "secret-D"
    assert "x-api-key" not in req.headers and "authorization" not in req.headers


async def test_app_credentials_401_not_retried(stack, downstream) -> None:
    downstream.responses["/v1/stock"] = [httpx.Response(401), httpx.Response(200)]
    with pytest.raises(OutboundServiceError) as exc:
        await ServiceClient(stack, "D").get("/v1/stock")
    assert exc.value.status_code == 401 and len(downstream.requests) == 1


async def test_credentials_isolated_between_services(stack, downstream) -> None:
    await ServiceClient(stack, "OPEN").get("/x")
    req = downstream.requests[-1]
    for name in ("authorization", "x-api-key", "x-application-id", "x-secret-key"):
        assert name not in req.headers


async def test_local_http_allowed_only_when_flagged(stack, downstream) -> None:
    await ServiceClient(stack, "LOCAL").get("/api/v1/orders")
    assert str(downstream.requests[-1].url) == "http://127.0.0.1:48081/api/v1/orders"


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.example.com/x",
        "//evil.example.com/x",
        "/../admin",
        "/a/./b",
        "relative",
        "/x?token=1",
        "/x#frag",
        "\\evil",
    ],
)
@pytest.mark.parametrize("service_id", ["A", "D"])
async def test_destination_cannot_escape_registered_origin(stack, downstream, path: str, service_id: str) -> None:
    with pytest.raises(OutboundSecurityException):
        await ServiceClient(stack, service_id).get(path)
    assert downstream.requests == []


async def test_redirects_not_followed(stack, downstream) -> None:
    downstream.responses["/v1/r"] = [httpx.Response(302, headers={"Location": "https://evil.example.com/steal"})]
    with pytest.raises(OutboundServiceError) as exc:
        await ServiceClient(stack, "D").get("/v1/r")
    assert exc.value.status_code == 302
    assert all(r.url.host != "evil.example.com" for r in downstream.requests)


@pytest.mark.parametrize(
    "header",
    ["Authorization", "x-api-key", "Cookie", "X-Application-Id", "x-secret-key", "Proxy-Authorization", "Host"],
)
@pytest.mark.parametrize("service_id", ["A", "D", "OPEN"])
async def test_caller_cannot_set_credential_headers(stack, downstream, header: str, service_id: str) -> None:
    with pytest.raises(OutboundSecurityException):
        await ServiceClient(stack, service_id).get("/x", headers={header: "forged"})
    assert downstream.requests == []


async def test_retries_only_idempotent(stack, downstream) -> None:
    downstream.responses["/api/get"] = [httpx.Response(503), httpx.Response(200)]
    assert (await ServiceClient(stack, "A").get("/get")).status_code == 200

    downstream.responses["/api/post"] = [httpx.Response(503), httpx.Response(200)]
    with pytest.raises(OutboundServiceError):
        await ServiceClient(stack, "A").post("/post", json={})

    downstream.responses["/api/post2"] = [httpx.Response(503), httpx.Response(200)]
    r = await ServiceClient(stack, "A").post("/post2", json={}, headers={"Idempotency-Key": "abc"})
    assert r.status_code == 200


async def test_error_message_has_no_query_or_secrets(stack, downstream) -> None:
    downstream.responses["/v1/x"] = [httpx.Response(400, json={"echo": "secret-D"})]
    with pytest.raises(OutboundServiceError) as exc:
        await ServiceClient(stack, "D").get("/v1/x", params={"token": "s3cr3t"})
    assert "s3cr3t" not in str(exc.value) and "secret-D" not in str(exc.value)


async def test_correlation_id_propagated(stack, downstream) -> None:
    token = correlation_id_var.set("corr-123")
    try:
        await ServiceClient(stack, "OPEN").get("/x")
    finally:
        correlation_id_var.reset(token)
    assert downstream.requests[-1].headers["X-Correlation-ID"] == "corr-123"


def test_unknown_service_rejected(stack) -> None:
    with pytest.raises(OutboundSecurityException):
        asyncio.run(stack.request("NOPE", "GET", "/x"))


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"base_url": "http://a.example.com", "auth_type": AuthType.NONE}, "must use https"),
        (
            {"base_url": "http://127.0.0.1:38081", "auth_type": AuthType.APP_CREDENTIALS, "credential_ref": "r"},
            "must use https",
        ),
        ({"base_url": "https://user:pw@a.example.com", "auth_type": AuthType.NONE}, "must not contain credentials"),
        ({"base_url": "https://a.example.com", "auth_type": AuthType.API_KEY}, "credential_ref is required"),
        ({"base_url": "https://a.example.com", "auth_type": AuthType.APP_CREDENTIALS}, "credential_ref is required"),
        ({"base_url": "https://a.example.com", "auth_type": AuthType.NONE, "unknown_field": 1}, "Extra inputs"),
    ],
)
def test_service_config_guardrails(kwargs, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        ServiceConfig(service_id="X", **kwargs)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://a.example.com",
        "http://10.0.0.5:48081",
        "http://192.168.1.10",
        "http://[2001:db8::1]:8080",
        "http://localhost.evil.com",
        "http://127.0.0.1.nip.io",
        "https://a.example.com",  # the flag itself is refused for non-loopback hosts
    ],
)
def test_allow_insecure_http_only_for_loopback(base_url: str) -> None:
    with pytest.raises(ValueError, match="only permitted for loopback hosts"):
        ServiceConfig(service_id="X", base_url=base_url, auth_type=AuthType.NONE, allow_insecure_http=True)


@pytest.mark.parametrize(
    "base_url", ["http://127.0.0.1:48081", "http://127.1.2.3", "http://localhost:38081", "http://[::1]:58081"]
)
def test_allow_insecure_http_accepted_for_loopback(base_url: str) -> None:
    config = ServiceConfig(service_id="X", base_url=base_url, auth_type=AuthType.NONE, allow_insecure_http=True)
    assert config.allow_insecure_http


def test_missing_or_duplicate_auth_strategy_fails_fast() -> None:
    with pytest.raises(OutboundSecurityException):
        InterceptorManager(
            auth_interceptors=[AppCredentialsInterceptor(FakeSecrets()), AppCredentialsInterceptor(FakeSecrets())]
        )
    with pytest.raises(OutboundSecurityException):
        InterceptorManager(auth_interceptors=[ApiKeyInterceptor(FakeSecrets())]).validate(ServiceRegistry(SERVICES))
    # BASIC/OAuth2 interceptors are not shipped in this app: such a service fails startup.
    basic = {
        "B": ServiceConfig(
            service_id="B", base_url="https://b.example.com", auth_type=AuthType.BASIC, credential_ref="b"
        )
    }
    with pytest.raises(OutboundSecurityException):
        InterceptorManager(auth_interceptors=[ApiKeyInterceptor(FakeSecrets())]).validate(ServiceRegistry(basic))


async def test_missing_secret_fails_clearly_without_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTBOUND_SVC_D__APPLICATION_ID", "app-D")
    monkeypatch.delenv("OUTBOUND_SVC_D__SECRET_KEY", raising=False)
    with pytest.raises(LookupError) as exc:
        await verify_outbound_secrets({"D": SERVICES["D"]}, EnvSecretStore())
    assert "OUTBOUND_SVC_D__SECRET_KEY" in str(exc.value) and "app-D" not in str(exc.value)


async def test_outbound_stack_fails_startup_without_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OUTBOUND_SVC_A__API_KEY", raising=False)
    with pytest.raises(LookupError):
        async with outbound_security(OutboundSettings(services={"A": SERVICES["A"]})):
            pass


def test_required_services_and_auth_types_enforced(outbound_settings: OutboundSettings) -> None:
    validate_outbound_settings(outbound_settings)
    with pytest.raises(RuntimeError):
        validate_outbound_settings(OutboundSettings(services={}))
    swapped = {
        "CALLED_APP": outbound_settings.services["CALLED_APP"].model_copy(
            update={"auth_type": AuthType.APP_CREDENTIALS}
        ),
        "ANOTHER_CALLED_APP": outbound_settings.services["ANOTHER_CALLED_APP"],
    }
    with pytest.raises(RuntimeError):
        validate_outbound_settings(OutboundSettings(services=swapped))


def test_outbound_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "SECURITY_OUTBOUND_SERVICES",
        '{"D": {"service_id": "D", "base_url": "https://d.example.com", "auth_type": "APP_CREDENTIALS", "credential_ref": "svc-d"}}',
    )
    assert OutboundSettings().services["D"].auth_type is AuthType.APP_CREDENTIALS
