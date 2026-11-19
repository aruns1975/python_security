"""MyCaller application (port 58081): API-key-protected service that calls CALLED_APP
(API key) and ANOTHER_CALLED_APP (application credentials).

Run: uvicorn --factory main:create_app --host 127.0.0.1 --port 58081
"""

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from api.errors import install_outbound_error_handlers
from api.routes import dashboard, inventory, orders
from clients.another_called_app_client import AnotherCalledAppClient
from clients.called_app_client import CalledAppClient
from security.configuration import (
    InboundSettings,
    OutboundSettings,
    build_providers,
    configure_inbound_security,
    outbound_security,
)
from security.outbound.credential_provider import SecretStore
from security.outbound.service_registry import AuthType

# Each downstream has exactly one auth strategy; a swapped or missing entry fails startup so
# one service's credentials can never be sent to the other.
REQUIRED_SERVICES: Mapping[str, AuthType] = {
    CalledAppClient.SERVICE_ID: AuthType.API_KEY,
    AnotherCalledAppClient.SERVICE_ID: AuthType.APP_CREDENTIALS,
}


def validate_outbound_settings(settings: OutboundSettings) -> None:
    for service_id, auth_type in REQUIRED_SERVICES.items():
        config = settings.services.get(service_id)
        if config is None:
            raise RuntimeError(f"Outbound service not configured: {service_id}")
        if config.auth_type is not auth_type:
            raise RuntimeError(f"{service_id} must use auth_type {auth_type}, got {config.auth_type}")


def create_app(
    inbound_settings: InboundSettings | None = None,
    outbound_settings: OutboundSettings | None = None,
    *,
    secrets: SecretStore | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    backoff_base_seconds: float = 0.2,
) -> FastAPI:
    """Application factory. Reads settings from the environment when none are given;
    missing security configuration raises here or in the lifespan, so the process never
    serves requests unprotected. `secrets` / `transport` are injection points for tests."""
    inbound = inbound_settings or InboundSettings()  # values come from the environment
    outbound = outbound_settings or OutboundSettings()
    validate_outbound_settings(outbound)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # One shared httpx.AsyncClient for the process, closed on shutdown.
        async with outbound_security(
            outbound, secrets=secrets, transport=transport, backoff_base_seconds=backoff_base_seconds
        ) as security:
            app.state.outbound = security
            app.state.called_app = CalledAppClient(security.client_for(CalledAppClient.SERVICE_ID))
            app.state.another_called_app = AnotherCalledAppClient(
                security.client_for(AnotherCalledAppClient.SERVICE_ID)
            )
            yield

    app = FastAPI(title="MyCaller application", lifespan=lifespan)
    configure_inbound_security(app, build_providers(inbound), inbound.public_paths, challenge_scheme="ApiKey")
    install_outbound_error_handlers(app)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(orders.router)
    app.include_router(inventory.router)
    app.include_router(dashboard.router)
    return app
