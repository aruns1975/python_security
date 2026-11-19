"""Inbound security tests for the Called application (testing.md §3 and §5 matrix)."""

import asyncio

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr, ValidationError
from starlette.requests import HTTPConnection

from main import create_app
from security.configuration import ApiKeyEntry, InboundSettings
from security.exceptions import AuthenticationException
from security.inbound.api_key_provider import ApiKeyRecord, InMemoryApiKeyStore, hash_api_key
from security.inbound.authentication_manager import AuthenticationManager
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.context_holder import SecurityContextHolder
from security.inbound.dependencies import CurrentPrincipal
from security.inbound.principal import SecurityPrincipal
from tests.conftest import DISABLED_KEY, NO_AUTHORITY_KEY, PEPPER, READER_KEY

API = "/api/v1/orders"


@pytest.mark.parametrize("path", ["/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"])
async def test_api_docs_are_public(client: httpx.AsyncClient, path: str) -> None:
    r = await client.get(path)
    assert r.status_code == 200


async def test_openapi_spec_documents_security_schemes(client: httpx.AsyncClient) -> None:
    spec = (await client.get("/openapi.json")).json()
    assert spec["components"]["securitySchemes"] == {"ApiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}


async def test_health_is_public(client: httpx.AsyncClient) -> None:
    r = await client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


@pytest.mark.parametrize("path", [API, f"{API}/ORD-1001"])
async def test_missing_credentials_401_with_challenge(client: httpx.AsyncClient, path: str) -> None:
    r = await client.get(path)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "ApiKey"
    assert r.json() == {"error": "unauthorized", "detail": "Authentication required"}


async def test_valid_key_lists_and_gets_orders(client: httpx.AsyncClient) -> None:
    r = await client.get(API, headers={"X-API-Key": READER_KEY})
    assert r.status_code == 200
    assert [o["id"] for o in r.json()] == ["ORD-1001", "ORD-1002", "ORD-1003"]
    r = await client.get(f"{API}/ORD-1002", headers={"X-API-Key": READER_KEY})
    assert r.status_code == 200 and r.json()["customer"] == "Globex"


async def test_unknown_order_404(client: httpx.AsyncClient) -> None:
    r = await client.get(f"{API}/ORD-9999", headers={"X-API-Key": READER_KEY})
    assert r.status_code == 404


@pytest.mark.parametrize("key", ["wrong", READER_KEY + "x", DISABLED_KEY, " ", ""])
async def test_wrong_or_disabled_key_401(client: httpx.AsyncClient, key: str) -> None:
    r = await client.get(API, headers={"X-API-Key": key})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "ApiKey"
    assert r.json()["detail"] == "Invalid API key"  # generic, no reason leaked


async def test_invalid_key_rejected_even_on_public_path(client: httpx.AsyncClient) -> None:
    assert (await client.get("/health", headers={"X-API-Key": "wrong"})).status_code == 401


async def test_missing_authority_403(client: httpx.AsyncClient) -> None:
    for path in (API, f"{API}/ORD-1001"):
        r = await client.get(path, headers={"X-API-Key": NO_AUTHORITY_KEY})
        assert r.status_code == 403
        assert r.json() == {"error": "forbidden", "detail": "Access denied"}


async def test_app_credentials_headers_are_not_accepted(client: httpx.AsyncClient) -> None:
    """This service accepts only API keys; another mechanism's headers are just anonymous."""
    r = await client.get(API, headers={"X-Application-Id": "mycaller-app", "X-Secret-Key": READER_KEY})
    assert r.status_code == 401


async def test_path_parameter_is_validated(client: httpx.AsyncClient) -> None:
    r = await client.get(f"{API}/bad%20id", headers={"X-API-Key": READER_KEY})
    assert r.status_code == 422


async def test_concurrent_requests_keep_their_own_principal(app: FastAPI, client: httpx.AsyncClient) -> None:
    @app.get("/test-only/whoami")
    async def whoami(principal: CurrentPrincipal) -> dict[str, str]:
        await asyncio.sleep(0.01)  # force interleaving between concurrent requests
        assert SecurityContextHolder.get_principal() is principal
        return {"subject": principal.subject}

    sent = [(READER_KEY, "svc:reader"), (NO_AUTHORITY_KEY, "svc:no-authority")] * 25
    responses = await asyncio.gather(*(client.get("/test-only/whoami", headers={"X-API-Key": k}) for k, _ in sent))
    assert [r.status_code for r in responses] == [200] * len(sent)
    assert [r.json()["subject"] for r in responses] == [subject for _, subject in sent]


async def test_credentials_never_logged(client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("DEBUG")
    await client.get(API, headers={"X-API-Key": READER_KEY})
    await client.get(API, headers={"X-API-Key": READER_KEY + "x"})
    await client.get(API)
    # Positive control: success and failures were logged (with reason codes), just without secrets.
    assert "Authentication successful" in caplog.text
    assert "API key authentication failed" in caplog.text
    assert "Authentication failed" in caplog.text
    assert {"invalid", "missing"} <= {getattr(r, "reason", None) for r in caplog.records}
    assert READER_KEY not in caplog.text and PEPPER not in caplog.text


# ---- fail-closed configuration ----


def test_settings_require_pepper_and_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECURITY_INBOUND_API_KEY_PEPPER", raising=False)
    monkeypatch.delenv("SECURITY_INBOUND_API_KEYS", raising=False)
    with pytest.raises(ValidationError):
        InboundSettings()
    with pytest.raises(ValidationError):
        InboundSettings(api_key_pepper=SecretStr(PEPPER), api_keys=())


def test_raw_key_in_hash_field_rejected() -> None:
    with pytest.raises(ValidationError):
        ApiKeyEntry(key_id="k", key_hash=READER_KEY, subject="s")


def test_short_pepper_fails_startup() -> None:
    entry = ApiKeyEntry(key_id="k", key_hash=hash_api_key(READER_KEY, b"short"), subject="s")
    with pytest.raises(ValueError, match="pepper must be at least 32 bytes"):
        create_app(InboundSettings(api_key_pepper=SecretStr("short"), api_keys=(entry,)))


def test_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = ApiKeyEntry(key_id="env", key_hash=hash_api_key(READER_KEY, PEPPER.encode()), subject="svc:env")
    monkeypatch.setenv("SECURITY_INBOUND_API_KEY_PEPPER", PEPPER)
    monkeypatch.setenv("SECURITY_INBOUND_API_KEYS", f"[{entry.model_dump_json()}]")
    settings = InboundSettings()
    assert settings.api_keys[0].key_id == "env"
    assert PEPPER not in repr(settings)  # SecretStr keeps the pepper out of reprs


async def test_context_reset_after_exception(app: FastAPI, client: httpx.AsyncClient) -> None:
    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("boom")

    r = await client.get("/boom", headers={"X-API-Key": READER_KEY})
    assert r.status_code == 500
    assert SecurityContextHolder.get_context() is None


def test_duplicate_key_hash_or_id_fails_startup() -> None:
    key_hash = hash_api_key(READER_KEY, PEPPER.encode())
    other_hash = hash_api_key(NO_AUTHORITY_KEY, PEPPER.encode())
    with pytest.raises(ValueError, match="Duplicate API key hashes"):
        InMemoryApiKeyStore([ApiKeyRecord("a", key_hash, "s1"), ApiKeyRecord("b", key_hash, "s2")])
    with pytest.raises(ValueError, match="Duplicate API key ids"):
        InMemoryApiKeyStore([ApiKeyRecord("a", key_hash, "s1"), ApiKeyRecord("a", other_hash, "s2")])
    dup = ApiKeyEntry(key_id="a", key_hash=key_hash, subject="s")
    with pytest.raises(ValueError, match="Duplicate API key"):
        create_app(InboundSettings(api_key_pepper=SecretStr(PEPPER), api_keys=(dup, dup)))


@pytest.mark.parametrize("paths", [("/",), ("/health", "/api/"), ("/docs/",), ("/health/",)])
def test_public_paths_restricted_to_allow_list(paths: tuple[str, ...]) -> None:
    entry = ApiKeyEntry(key_id="k", key_hash=hash_api_key(READER_KEY, PEPPER.encode()), subject="s")
    with pytest.raises(ValidationError, match="public_paths not allowed"):
        InboundSettings(api_key_pepper=SecretStr(PEPPER), api_keys=(entry,), public_paths=paths)


class _AlwaysSupports(AuthenticationProvider):
    name = "ALWAYS_A"

    def supports(self, connection: HTTPConnection) -> bool:
        return True

    async def authenticate(self, connection: HTTPConnection) -> SecurityPrincipal:
        raise AssertionError("must not be reached on ambiguous requests")


class _AlsoAlwaysSupports(_AlwaysSupports):
    name = "ALWAYS_B"


async def test_ambiguous_credentials_carry_reason_code() -> None:
    manager = AuthenticationManager([_AlwaysSupports(), _AlsoAlwaysSupports()])
    with pytest.raises(AuthenticationException, match="Ambiguous") as exc:
        await manager.authenticate(HTTPConnection({"type": "http", "path": "/", "headers": []}))
    assert exc.value.reason == "ambiguous"
