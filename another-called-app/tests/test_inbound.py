"""Inbound security tests for the Another Called application (testing.md §5 matrix for a
new auth provider: valid, invalid, missing, partial, ambiguous-with-other-provider)."""

import asyncio
import hmac

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr, ValidationError
from starlette.requests import HTTPConnection

from main import create_app
from security.configuration import AppCredentialEntry, InboundSettings
from security.exceptions import AuthenticationException
from security.inbound.app_credentials_provider import (
    AppCredentialRecord,
    AppCredentialsAuthenticationProvider,
    InMemoryAppCredentialStore,
    hash_secret_key,
)
from security.inbound.authentication_manager import AuthenticationManager
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.context_holder import SecurityContextHolder
from security.inbound.dependencies import CurrentPrincipal
from security.inbound.principal import SecurityPrincipal
from tests.conftest import (
    APP_ID,
    DISABLED_APP_ID,
    DISABLED_SECRET,
    NO_AUTHORITY_APP_ID,
    NO_AUTHORITY_SECRET,
    PEPPER,
    SECRET,
    creds,
)

API = "/api/v1/inventory"


def _connection(headers: dict[str, str]) -> HTTPConnection:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return HTTPConnection({"type": "http", "path": "/", "headers": raw})


@pytest.mark.parametrize("path", ["/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"])
async def test_api_docs_are_public(client: httpx.AsyncClient, path: str) -> None:
    r = await client.get(path)
    assert r.status_code == 200


async def test_openapi_spec_documents_security_schemes(client: httpx.AsyncClient) -> None:
    spec = (await client.get("/openapi.json")).json()
    schemes = spec["components"]["securitySchemes"]
    # Both headers must be offered by Swagger's Authorize dialog, or "Try it out" can never succeed.
    assert {(s["in"], s["name"]) for s in schemes.values()} == {("header", "X-Application-Id"), ("header", "X-Secret-Key")}
    operation = spec["paths"]["/api/v1/inventory"]["get"]
    assert {name for requirement in operation["security"] for name in requirement} == set(schemes)


async def test_health_is_public(client: httpx.AsyncClient) -> None:
    r = await client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


@pytest.mark.parametrize("path", [API, f"{API}/SKU-100"])
async def test_missing_credentials_401_with_challenge(client: httpx.AsyncClient, path: str) -> None:
    r = await client.get(path)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "AppCredentials"


async def test_valid_credentials(client: httpx.AsyncClient) -> None:
    r = await client.get(API, headers=creds())
    assert r.status_code == 200
    assert [i["sku"] for i in r.json()] == ["SKU-100", "SKU-200", "SKU-300"]
    r = await client.get(f"{API}/SKU-300", headers=creds())
    assert r.status_code == 200 and r.json()["name"] == "Cold-chain sensor"
    assert (await client.get(f"{API}/SKU-999", headers=creds())).status_code == 404


async def test_principal_fields() -> None:
    record = AppCredentialRecord(
        APP_ID,
        hash_secret_key(APP_ID, SECRET, PEPPER.encode()),
        "svc:reader",
        authorities=frozenset({"INVENTORY_READ"}),
    )
    provider = AppCredentialsAuthenticationProvider(InMemoryAppCredentialStore([record]), PEPPER.encode())
    principal = await provider.authenticate(_connection(creds()))
    assert principal.subject == "svc:reader"
    assert principal.authentication_type == "APP_CREDENTIALS"
    assert principal.authorities == frozenset({"INVENTORY_READ"})
    assert dict(principal.claims) == {"application_id": APP_ID}


@pytest.mark.parametrize(
    "headers",
    [
        creds(secret_key="wrong-secret"),
        creds(secret_key=SECRET + "x"),
        creds(application_id="unknown-app"),
        creds(application_id=NO_AUTHORITY_APP_ID, secret_key=SECRET),  # secret of another app
        creds(application_id=DISABLED_APP_ID, secret_key=DISABLED_SECRET),
        creds(application_id=" ", secret_key=SECRET),
        creds(secret_key="x" * 600),
    ],
)
async def test_wrong_credentials_401(client: httpx.AsyncClient, headers: dict[str, str]) -> None:
    r = await client.get(API, headers=headers)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "AppCredentials"
    assert r.json()["detail"] == "Invalid application credentials"  # generic, no reason leaked


@pytest.mark.parametrize("path", [API, "/health"])
@pytest.mark.parametrize(
    "headers",
    [{"X-Application-Id": APP_ID}, {"X-Secret-Key": SECRET}],
    ids=["application-id-only", "secret-key-only"],
)
async def test_partial_headers_401_even_on_public_path(
    client: httpx.AsyncClient, path: str, headers: dict[str, str]
) -> None:
    r = await client.get(path, headers=headers)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "AppCredentials"


async def test_invalid_credentials_rejected_on_public_path(client: httpx.AsyncClient) -> None:
    assert (await client.get("/health", headers=creds(secret_key="wrong"))).status_code == 401


async def test_missing_authority_403(client: httpx.AsyncClient) -> None:
    for path in (API, f"{API}/SKU-100"):
        r = await client.get(path, headers=creds(NO_AUTHORITY_APP_ID, NO_AUTHORITY_SECRET))
        assert r.status_code == 403
        assert r.json() == {"error": "forbidden", "detail": "Access denied"}


async def test_api_key_is_not_accepted(client: httpx.AsyncClient) -> None:
    """This service accepts only app credentials; an API key is just anonymous."""
    r = await client.get(API, headers={"X-API-Key": SECRET})
    assert r.status_code == 401


async def test_unknown_application_id_still_runs_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    """Timing-enumeration guard: unknown IDs take the same hash + compare_digest path."""
    calls: list[tuple[str, str]] = []
    real_compare = hmac.compare_digest

    def spy(a: str, b: str) -> bool:
        calls.append((a, b))
        return real_compare(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    record = AppCredentialRecord(APP_ID, hash_secret_key(APP_ID, SECRET, PEPPER.encode()), "svc:reader")
    provider = AppCredentialsAuthenticationProvider(InMemoryAppCredentialStore([record]), PEPPER.encode())
    with pytest.raises(AuthenticationException):
        await provider.authenticate(_connection(creds(application_id="unknown-app")))
    assert len(calls) == 1
    expected, presented = calls[0]
    assert expected != record.secret_hash and len(expected) == len(presented) == 64


class _BearerStub(AuthenticationProvider):
    name = "STUB_BEARER"

    def supports(self, connection: HTTPConnection) -> bool:
        return "authorization" in connection.headers

    async def authenticate(self, connection: HTTPConnection) -> SecurityPrincipal:
        raise AssertionError("must not be reached on ambiguous requests")


async def test_ambiguous_with_other_provider_rejected() -> None:
    record = AppCredentialRecord(APP_ID, hash_secret_key(APP_ID, SECRET, PEPPER.encode()), "svc:reader")
    manager = AuthenticationManager(
        [AppCredentialsAuthenticationProvider(InMemoryAppCredentialStore([record]), PEPPER.encode()), _BearerStub()]
    )
    with pytest.raises(AuthenticationException, match="Ambiguous"):
        await manager.authenticate(_connection({**creds(), "Authorization": "Bearer x"}))
    assert (await manager.authenticate(_connection({}))) is None  # missing -> anonymous


async def test_concurrent_requests_keep_their_own_principal(app: FastAPI, client: httpx.AsyncClient) -> None:
    @app.get("/test-only/whoami")
    async def whoami(principal: CurrentPrincipal) -> dict[str, str]:
        await asyncio.sleep(0.01)  # force interleaving between concurrent requests
        assert SecurityContextHolder.get_principal() is principal
        return {"subject": principal.subject}

    sent = [(APP_ID, SECRET), (NO_AUTHORITY_APP_ID, NO_AUTHORITY_SECRET)] * 25
    responses = await asyncio.gather(*(client.get("/test-only/whoami", headers=creds(*c)) for c in sent))
    assert [r.status_code for r in responses] == [200] * len(sent)
    assert [r.json()["subject"] for r in responses] == [f"svc:{app_id}" for app_id, _ in sent]


async def test_context_reset_after_exception(app: FastAPI, client: httpx.AsyncClient) -> None:
    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("boom")

    r = await client.get("/boom", headers=creds())
    assert r.status_code == 500
    assert SecurityContextHolder.get_context() is None


async def test_credentials_never_logged(client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("DEBUG")
    await client.get(API, headers=creds())
    await client.get(API, headers=creds(secret_key=SECRET + "x"))
    await client.get(API, headers={"X-Secret-Key": SECRET})
    # Positive control: the failures were logged (with reason codes), just without secrets.
    assert "App credentials authentication failed" in caplog.text
    assert "Authentication failed" in caplog.text
    reasons = {getattr(r, "reason", None) for r in caplog.records}
    assert {"invalid", "partial_headers"} <= reasons
    assert SECRET not in caplog.text and PEPPER not in caplog.text


# ---- fail-closed configuration ----


def test_settings_require_pepper_and_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECURITY_INBOUND_APP_CREDENTIALS_PEPPER", raising=False)
    monkeypatch.delenv("SECURITY_INBOUND_APP_CREDENTIALS", raising=False)
    with pytest.raises(ValidationError):
        InboundSettings()
    with pytest.raises(ValidationError):
        InboundSettings(app_credentials_pepper=SecretStr(PEPPER), app_credentials=())


def test_raw_secret_in_hash_field_rejected() -> None:
    with pytest.raises(ValidationError):
        AppCredentialEntry(application_id="a", secret_hash=SECRET, subject="s")


def test_short_pepper_and_duplicate_ids_fail_startup() -> None:
    entry = AppCredentialEntry(application_id="a", secret_hash=hash_secret_key("a", SECRET, b"short"), subject="s")
    with pytest.raises(ValueError, match="pepper must be at least 32 bytes"):
        create_app(InboundSettings(app_credentials_pepper=SecretStr("short"), app_credentials=(entry,)))
    with pytest.raises(ValueError, match="Duplicate application IDs"):
        create_app(InboundSettings(app_credentials_pepper=SecretStr(PEPPER), app_credentials=(entry, entry)))


def test_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = AppCredentialEntry(
        application_id="env-app", secret_hash=hash_secret_key("env-app", SECRET, PEPPER.encode()), subject="svc:env"
    )
    monkeypatch.setenv("SECURITY_INBOUND_APP_CREDENTIALS_PEPPER", PEPPER)
    monkeypatch.setenv("SECURITY_INBOUND_APP_CREDENTIALS", f"[{entry.model_dump_json()}]")
    settings = InboundSettings()
    assert settings.app_credentials[0].application_id == "env-app"
    assert PEPPER not in repr(settings)


async def test_hash_is_bound_to_application_id(settings: InboundSettings) -> None:
    """Copying app A's stored hash onto app B must not let B authenticate with A's secret."""
    a_hash = hash_secret_key(APP_ID, SECRET, PEPPER.encode())
    assert a_hash != hash_secret_key(NO_AUTHORITY_APP_ID, SECRET, PEPPER.encode())
    copied = AppCredentialRecord(NO_AUTHORITY_APP_ID, a_hash, "svc:copied", authorities=frozenset({"INVENTORY_READ"}))
    provider = AppCredentialsAuthenticationProvider(InMemoryAppCredentialStore([copied]), PEPPER.encode())
    with pytest.raises(AuthenticationException):
        await provider.authenticate(_connection(creds(NO_AUTHORITY_APP_ID, SECRET)))


async def test_failure_reason_codes() -> None:
    record = AppCredentialRecord(APP_ID, hash_secret_key(APP_ID, SECRET, PEPPER.encode()), "svc:reader")
    provider = AppCredentialsAuthenticationProvider(InMemoryAppCredentialStore([record]), PEPPER.encode())
    for headers, reason in (
        ({"X-Application-Id": APP_ID}, "partial_headers"),
        ({"X-Secret-Key": SECRET}, "partial_headers"),
        (creds(secret_key="wrong"), "invalid"),
    ):
        with pytest.raises(AuthenticationException) as exc:
            await provider.authenticate(_connection(headers))
        assert exc.value.reason == reason
        assert reason not in str(exc.value)  # reason is for logs only, not the client message


@pytest.mark.parametrize("paths", [("/",), ("/health", "/api/"), ("/docs/",), ("/health/",)])
def test_public_paths_restricted_to_allow_list(paths: tuple[str, ...]) -> None:
    with pytest.raises(ValidationError, match="public_paths not allowed"):
        InboundSettings(
            app_credentials_pepper=SecretStr(PEPPER),
            app_credentials=(
                AppCredentialEntry(
                    application_id=APP_ID, secret_hash=hash_secret_key(APP_ID, SECRET, PEPPER.encode()), subject="s"
                ),
            ),
            public_paths=paths,
        )


def test_application_id_charset_enforced() -> None:
    with pytest.raises(ValidationError, match="application_id"):
        AppCredentialEntry(application_id="bad\x00id", secret_hash="0" * 64, subject="s")
