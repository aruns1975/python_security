"""End-to-end (in-process) outbound tests: inbound request -> service layer -> typed client ->
SecureHttpClient -> httpx.MockTransport. Asserts which credentials reach which service."""

import httpx
import pytest
from fastapi import FastAPI

from tests.conftest import (
    ANOTHER_APP_ID,
    ANOTHER_HOST,
    ANOTHER_SECRET_KEY,
    CALLED_APP_API_KEY,
    CALLED_HOST,
    DASHBOARD_KEY,
    INVENTORY,
    ORDERS,
    Downstream,
    key,
)

APP_CREDENTIAL_HEADERS = ("x-application-id", "x-secret-key")


def assert_called_app_credentials(request: httpx.Request) -> None:
    assert request.url.scheme == "https" and request.url.host == CALLED_HOST
    assert request.headers["X-API-Key"] == CALLED_APP_API_KEY
    for name in (*APP_CREDENTIAL_HEADERS, "authorization", "cookie"):
        assert name not in request.headers, name


def assert_another_called_app_credentials(request: httpx.Request) -> None:
    assert request.url.scheme == "https" and request.url.host == ANOTHER_HOST
    assert request.headers["X-Application-Id"] == ANOTHER_APP_ID
    assert request.headers["X-Secret-Key"] == ANOTHER_SECRET_KEY
    for name in ("x-api-key", "authorization", "cookie"):
        assert name not in request.headers, name


async def test_orders_use_api_key_only(client: httpx.AsyncClient, downstream: Downstream) -> None:
    r = await client.get("/api/v1/orders", headers=key(DASHBOARD_KEY))
    assert r.status_code == 200 and r.json() == ORDERS
    assert len(downstream.requests) == 1
    request = downstream.requests[0]
    assert_called_app_credentials(request)
    assert str(request.url) == f"https://{CALLED_HOST}/api/v1/orders"


async def test_inventory_uses_app_credentials_only(client: httpx.AsyncClient, downstream: Downstream) -> None:
    r = await client.get("/api/v1/inventory/SKU-1", headers=key(DASHBOARD_KEY))
    assert r.status_code == 200 and r.json() == INVENTORY[0]
    assert len(downstream.requests) == 1
    assert_another_called_app_credentials(downstream.requests[0])


async def test_dashboard_calls_both_with_isolated_credentials(
    client: httpx.AsyncClient, downstream: Downstream
) -> None:
    r = await client.get("/api/v1/dashboard", headers=key(DASHBOARD_KEY))
    assert r.status_code == 200
    body = r.json()
    assert body["orders"] == ORDERS and body["inventory"] == INVENTORY
    assert body["order_count"] == 2 and body["order_total"] == 15.0 and body["inventory_units"] == 10
    called, another = downstream.for_host(CALLED_HOST), downstream.for_host(ANOTHER_HOST)
    assert len(called) == 1 and len(another) == 1 and len(downstream.requests) == 2
    assert_called_app_credentials(called[0])
    assert_another_called_app_credentials(another[0])


async def test_inbound_client_key_is_never_forwarded(client: httpx.AsyncClient, downstream: Downstream) -> None:
    await client.get("/api/v1/dashboard", headers=key(DASHBOARD_KEY))
    for request in downstream.requests:
        assert DASHBOARD_KEY not in str(request.headers.raw)


@pytest.mark.parametrize(
    ("host", "path", "response"),
    [
        (CALLED_HOST, "/api/v1/orders", httpx.Response(500, json={"trace": "db password leaked"})),
        (ANOTHER_HOST, "/api/v1/inventory", httpx.Response(401, json={"detail": "bad secret"})),
        (CALLED_HOST, "/api/v1/orders", httpx.Response(200, json=[{"id": "ORD-1"}])),  # schema mismatch
        (ANOTHER_HOST, "/api/v1/inventory", httpx.Response(200, content=b"<html>not json</html>")),
        (CALLED_HOST, "/api/v1/orders", httpx.Response(302, headers={"Location": "https://evil.example.com/"})),
    ],
    ids=["500", "401", "invalid-schema", "not-json", "redirect"],
)
async def test_downstream_failure_becomes_clean_502(
    client: httpx.AsyncClient, downstream: Downstream, host: str, path: str, response: httpx.Response
) -> None:
    # Queue enough failures to exhaust retries (3 attempts for GET 5xx).
    downstream.queue(host, path, response, response, response)
    r = await client.get("/api/v1/dashboard", headers=key(DASHBOARD_KEY))
    assert r.status_code == 502
    assert r.json() == {"error": "bad_gateway", "detail": "Upstream service error"}
    for leak in ("CALLED_APP", "ANOTHER_CALLED_APP", "password", "secret", CALLED_HOST, ANOTHER_HOST, "evil"):
        assert leak not in r.text
    assert all(req.url.host != "evil.example.com" for req in downstream.requests)


async def test_transport_error_becomes_502(client: httpx.AsyncClient, downstream: Downstream) -> None:
    downstream.unreachable_hosts.add(ANOTHER_HOST)
    r = await client.get("/api/v1/dashboard", headers=key(DASHBOARD_KEY))
    assert r.status_code == 502 and r.json()["detail"] == "Upstream service error"
    assert len(downstream.for_host(ANOTHER_HOST)) == 3  # GET retried max_retries times


async def test_downstream_404_maps_to_404(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/v1/orders/ORD-404", headers=key(DASHBOARD_KEY))).status_code == 404
    assert (await client.get("/api/v1/inventory/SKU-404", headers=key(DASHBOARD_KEY))).status_code == 404


async def test_transient_503_is_retried(client: httpx.AsyncClient, downstream: Downstream) -> None:
    downstream.queue(CALLED_HOST, "/api/v1/orders", httpx.Response(503))
    r = await client.get("/api/v1/orders", headers=key(DASHBOARD_KEY))
    assert r.status_code == 200 and len(downstream.for_host(CALLED_HOST)) == 2
    assert all(req.headers["X-API-Key"] == CALLED_APP_API_KEY for req in downstream.for_host(CALLED_HOST))


async def test_outbound_secrets_never_logged(
    client: httpx.AsyncClient, downstream: Downstream, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    downstream.queue(ANOTHER_HOST, "/api/v1/inventory", httpx.Response(500), httpx.Response(500), httpx.Response(500))
    await client.get("/api/v1/orders", headers=key(DASHBOARD_KEY))
    await client.get("/api/v1/dashboard", headers=key(DASHBOARD_KEY))
    # Positive control: outbound calls and the 502 were logged, just without secrets.
    assert "Outbound request completed" in caplog.text
    assert "Downstream call failed" in caplog.text
    assert {"CALLED_APP", "ANOTHER_CALLED_APP"} <= {getattr(r, "service_id", None) for r in caplog.records}
    for secret in (CALLED_APP_API_KEY, ANOTHER_APP_ID, ANOTHER_SECRET_KEY, DASHBOARD_KEY):
        assert secret not in caplog.text


async def test_set_cookie_is_never_stored_or_replayed(
    app: FastAPI, client: httpx.AsyncClient, downstream: Downstream
) -> None:
    """A Set-Cookie from one downstream must not reach the other service (or later callers)."""
    downstream.queue(
        CALLED_HOST,
        "/api/v1/orders",
        httpx.Response(200, json=ORDERS, headers={"Set-Cookie": "session=leak; Path=/; Domain=internal"}),
    )
    downstream.queue(
        ANOTHER_HOST,
        "/api/v1/inventory",
        httpx.Response(200, json=INVENTORY, headers={"Set-Cookie": "other=leak; Path=/"}),
    )
    await client.get("/api/v1/orders", headers=key(DASHBOARD_KEY))
    await client.get("/api/v1/inventory", headers=key(DASHBOARD_KEY))
    for _ in range(2):
        assert (await client.get("/api/v1/dashboard", headers=key(DASHBOARD_KEY))).status_code == 200
    assert len(downstream.requests) == 6
    assert all("cookie" not in r.headers for r in downstream.requests)
    assert len(app.state.outbound.http_client.cookies.jar) == 0


async def test_shared_client_ignores_proxy_environment(app: FastAPI) -> None:
    assert app.state.outbound.http_client.trust_env is False
