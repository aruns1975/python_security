from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from main import create_app
from security.configuration import ApiKeyEntry, InboundSettings, OutboundSettings
from security.inbound.api_key_provider import hash_api_key
from security.outbound.service_registry import AuthType, ServiceConfig

# Test-only values, generated for the suite; never used outside tests.
PEPPER = "test-pepper-" + "m" * 32
DASHBOARD_KEY = "test-client-dashboard-0123456789abcdef"
ORDERS_ONLY_KEY = "test-client-orders-0123456789abcdef"
NO_AUTHORITY_KEY = "test-client-noauth-0123456789abcdef"

# Outbound secrets the fake secret store hands to the interceptors.
CALLED_APP_API_KEY = "test-outbound-called-app-key"
ANOTHER_APP_ID = "test-mycaller-app-id"
ANOTHER_SECRET_KEY = "test-outbound-another-secret"
SECRETS = {
    ("called-app", "api_key"): CALLED_APP_API_KEY,
    ("another-called-app", "application_id"): ANOTHER_APP_ID,
    ("another-called-app", "secret_key"): ANOTHER_SECRET_KEY,
}

CALLED_HOST = "called-app.internal"
ANOTHER_HOST = "another-called-app.internal"

ORDERS = [
    {"id": "ORD-1", "customer": "Acme", "status": "SHIPPED", "total": 10.5},
    {"id": "ORD-2", "customer": "Globex", "status": "PENDING", "total": 4.5},
]
INVENTORY = [
    {"sku": "SKU-1", "name": "Pallet jack", "quantity": 3, "warehouse": "CHI-1"},
    {"sku": "SKU-2", "name": "Sensor", "quantity": 7, "warehouse": "DAL-2"},
]


class FakeSecrets:
    async def get_secret(self, reference: str, key: str) -> str:
        try:
            return SECRETS[(reference, key)]
        except KeyError:
            raise LookupError(f"Secret not configured: {reference}/{key}") from None


class Downstream:
    """Fake network for both downstream services: records every request."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.responses: dict[tuple[str, str], list[httpx.Response]] = {}
        self.unreachable_hosts: set[str] = set()

    def queue(self, host: str, path: str, *responses: httpx.Response) -> None:
        self.responses.setdefault((host, path), []).extend(responses)

    def for_host(self, host: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == host]

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host in self.unreachable_hosts:
            raise httpx.ConnectError("connection refused", request=request)
        queued = self.responses.get((request.url.host, request.url.path))
        if queued:
            return queued.pop(0)
        routes = {
            (CALLED_HOST, "/api/v1/orders"): ORDERS,
            (CALLED_HOST, "/api/v1/orders/ORD-1"): ORDERS[0],
            (ANOTHER_HOST, "/api/v1/inventory"): INVENTORY,
            (ANOTHER_HOST, "/api/v1/inventory/SKU-1"): INVENTORY[0],
        }
        body = routes.get((request.url.host, request.url.path))
        if body is None:
            return httpx.Response(404, json={"detail": "not found"})
        return httpx.Response(200, json=body)


def _entry(key_id: str, key: str, authorities: set[str]) -> ApiKeyEntry:
    return ApiKeyEntry(
        key_id=key_id,
        key_hash=hash_api_key(key, PEPPER.encode()),
        subject=f"client:{key_id}",
        authorities=frozenset(authorities),
    )


@pytest.fixture
def inbound_settings() -> InboundSettings:
    return InboundSettings(
        api_key_pepper=SecretStr(PEPPER),
        api_keys=(
            _entry("dashboard", DASHBOARD_KEY, {"ORDER_READ", "INVENTORY_READ", "DASHBOARD_READ"}),
            _entry("orders-only", ORDERS_ONLY_KEY, {"ORDER_READ"}),
            _entry("no-authority", NO_AUTHORITY_KEY, set()),
        ),
    )


@pytest.fixture
def outbound_settings() -> OutboundSettings:
    return OutboundSettings(
        services={
            "CALLED_APP": ServiceConfig(
                service_id="CALLED_APP",
                base_url=f"https://{CALLED_HOST}",
                auth_type=AuthType.API_KEY,
                credential_ref="called-app",
            ),
            "ANOTHER_CALLED_APP": ServiceConfig(
                service_id="ANOTHER_CALLED_APP",
                base_url=f"https://{ANOTHER_HOST}",
                auth_type=AuthType.APP_CREDENTIALS,
                credential_ref="another-called-app",
            ),
        }
    )


@pytest.fixture
def downstream() -> Downstream:
    return Downstream()


@pytest.fixture
async def app(
    inbound_settings: InboundSettings, outbound_settings: OutboundSettings, downstream: Downstream
) -> AsyncIterator[FastAPI]:
    app = create_app(
        inbound_settings,
        outbound_settings,
        secrets=FakeSecrets(),
        transport=httpx.MockTransport(downstream),
        backoff_base_seconds=0,
    )
    # ASGITransport does not run the lifespan; run it explicitly so the real outbound stack is built.
    async with app.router.lifespan_context(app):
        yield app


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test"
    ) as c:
        yield c


def key(value: str) -> dict[str, str]:
    return {"X-API-Key": value}
