"""Inbound security tests for MyCaller (testing.md §5: new protected endpoints)."""

import asyncio

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr, ValidationError

from security.configuration import ApiKeyEntry, InboundSettings
from security.inbound.api_key_provider import ApiKeyRecord, InMemoryApiKeyStore, hash_api_key
from security.inbound.context_holder import SecurityContextHolder
from security.inbound.dependencies import CurrentPrincipal
from tests.conftest import (
    CALLED_APP_API_KEY,
    DASHBOARD_KEY,
    NO_AUTHORITY_KEY,
    ORDERS_ONLY_KEY,
    PEPPER,
    key,
)

PROTECTED = [
    "/api/v1/orders",
    "/api/v1/orders/ORD-1",
    "/api/v1/inventory",
    "/api/v1/inventory/SKU-1",
    "/api/v1/dashboard",
]


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


@pytest.mark.parametrize("path", [*PROTECTED])
async def test_missing_credentials_401(client: httpx.AsyncClient, path: str) -> None:
    r = await client.get(path)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "ApiKey"


@pytest.mark.parametrize("value", ["wrong", DASHBOARD_KEY + "x", CALLED_APP_API_KEY, ""])
async def test_wrong_key_401(client: httpx.AsyncClient, value: str) -> None:
    """Includes the outbound key for CALLED_APP: it is not a MyCaller client key."""
    r = await client.get("/api/v1/dashboard", headers=key(value))
    assert r.status_code == 401 and r.json()["detail"] == "Invalid API key"


async def test_app_credentials_headers_are_not_accepted(client: httpx.AsyncClient) -> None:
    r = await client.get("/api/v1/orders", headers={"X-Application-Id": "x", "X-Secret-Key": DASHBOARD_KEY})
    assert r.status_code == 401


async def test_valid_key_all_endpoints(client: httpx.AsyncClient) -> None:
    for path in PROTECTED:
        assert (await client.get(path, headers=key(DASHBOARD_KEY))).status_code == 200, path


@pytest.mark.parametrize(
    ("value", "path", "status"),
    [
        (ORDERS_ONLY_KEY, "/api/v1/orders", 200),
        (ORDERS_ONLY_KEY, "/api/v1/orders/ORD-1", 200),
        (ORDERS_ONLY_KEY, "/api/v1/inventory", 403),
        (ORDERS_ONLY_KEY, "/api/v1/inventory/SKU-1", 403),
        (ORDERS_ONLY_KEY, "/api/v1/dashboard", 403),
        (NO_AUTHORITY_KEY, "/api/v1/orders", 403),
        (NO_AUTHORITY_KEY, "/api/v1/dashboard", 403),
    ],
)
async def test_authority_matrix(client: httpx.AsyncClient, value: str, path: str, status: int) -> None:
    r = await client.get(path, headers=key(value))
    assert r.status_code == status
    if status == 403:
        assert r.json() == {"error": "forbidden", "detail": "Access denied"}


async def test_denied_request_makes_no_downstream_call(client: httpx.AsyncClient, downstream) -> None:
    await client.get("/api/v1/dashboard", headers=key(ORDERS_ONLY_KEY))
    await client.get("/api/v1/dashboard")
    assert downstream.requests == []


async def test_path_parameter_is_validated(client: httpx.AsyncClient, downstream) -> None:
    r = await client.get("/api/v1/orders/bad%20id", headers=key(DASHBOARD_KEY))
    assert r.status_code == 422 and downstream.requests == []


async def test_concurrent_requests_keep_their_own_principal(app: FastAPI, client: httpx.AsyncClient) -> None:
    @app.get("/test-only/whoami")
    async def whoami(principal: CurrentPrincipal) -> dict[str, str]:
        await asyncio.sleep(0.01)  # force interleaving between concurrent requests
        assert SecurityContextHolder.get_principal() is principal
        return {"subject": principal.subject}

    sent = [(DASHBOARD_KEY, "client:dashboard"), (ORDERS_ONLY_KEY, "client:orders-only")] * 25
    responses = await asyncio.gather(*(client.get("/test-only/whoami", headers=key(k)) for k, _ in sent))
    assert [r.status_code for r in responses] == [200] * len(sent)
    assert [r.json()["subject"] for r in responses] == [subject for _, subject in sent]


async def test_context_reset_after_exception(app: FastAPI, client: httpx.AsyncClient) -> None:
    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("boom")

    r = await client.get("/boom", headers=key(DASHBOARD_KEY))
    assert r.status_code == 500
    assert SecurityContextHolder.get_context() is None


async def test_credentials_never_logged(client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("DEBUG")
    await client.get("/api/v1/dashboard", headers=key(DASHBOARD_KEY))
    await client.get("/api/v1/dashboard", headers=key(DASHBOARD_KEY + "x"))
    await client.get("/api/v1/dashboard", headers=key(ORDERS_ONLY_KEY))
    # Positive control: success, failure and denial were logged, just without secrets.
    assert "Authentication successful" in caplog.text
    assert "API key authentication failed" in caplog.text
    assert "Authorization denied" in caplog.text
    assert "invalid" in {getattr(r, "reason", None) for r in caplog.records}
    assert DASHBOARD_KEY not in caplog.text and ORDERS_ONLY_KEY not in caplog.text and PEPPER not in caplog.text


def test_duplicate_key_hash_or_id_fails_startup() -> None:
    key_hash = hash_api_key(DASHBOARD_KEY, PEPPER.encode())
    other_hash = hash_api_key(ORDERS_ONLY_KEY, PEPPER.encode())
    with pytest.raises(ValueError, match="Duplicate API key hashes"):
        InMemoryApiKeyStore([ApiKeyRecord("a", key_hash, "s1"), ApiKeyRecord("b", key_hash, "s2")])
    with pytest.raises(ValueError, match="Duplicate API key ids"):
        InMemoryApiKeyStore([ApiKeyRecord("a", key_hash, "s1"), ApiKeyRecord("a", other_hash, "s2")])


@pytest.mark.parametrize("paths", [("/",), ("/health", "/api/"), ("/docs/",), ("/api/v1/dashboard",)])
def test_public_paths_restricted_to_allow_list(paths: tuple[str, ...]) -> None:
    entry = ApiKeyEntry(key_id="k", key_hash=hash_api_key(DASHBOARD_KEY, PEPPER.encode()), subject="s")
    with pytest.raises(ValidationError, match="public_paths not allowed"):
        InboundSettings(api_key_pepper=SecretStr(PEPPER), api_keys=(entry,), public_paths=paths)
