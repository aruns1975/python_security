"""Example application wiring. Run: uvicorn main:app"""
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Request

from security.configuration import (
    InboundSettings,
    OutboundSecurity,
    OutboundSettings,
    configure_inbound_security,
    outbound_security,
)
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.decorators import pre_authorize
from security.inbound.dependencies import CurrentPrincipal, require_authority
from security.inbound.jwt_provider import JwtAuthenticationProvider, JwtSettings
from security.inbound.policies import has_authority
from security.outbound.service_client import ServiceClient


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with outbound_security(OutboundSettings()) as outbound:
        app.state.outbound = outbound
        yield


def build_providers(settings: InboundSettings) -> list[AuthenticationProvider]:
    providers: list[AuthenticationProvider] = []
    if settings.jwt_enabled:
        providers.append(
            JwtAuthenticationProvider(
                JwtSettings(
                    issuer=settings.jwt_issuer,
                    audience=settings.jwt_audience,
                    jwks_url=settings.jwt_jwks_url,
                    algorithms=settings.jwt_algorithms,
                )
            )
        )
    return providers


inbound_settings = InboundSettings()
app = FastAPI(lifespan=lifespan)
configure_inbound_security(app, build_providers(inbound_settings), inbound_settings.public_paths)


def billing_client(request: Request) -> ServiceClient:
    outbound: OutboundSecurity = request.app.state.outbound
    return outbound.client_for("BILLING")


class InvoiceService:
    def __init__(self, billing: ServiceClient) -> None:
        self._billing = billing

    @pre_authorize(has_authority("INVOICE_READ"))
    async def list_invoices(self, customer_id: str) -> list[dict]:
        response = await self._billing.get("/v1/invoices", params={"customer": customer_id})
        return response.json()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/invoices", dependencies=[Depends(require_authority("INVOICE_READ"))])
async def list_invoices(
    principal: CurrentPrincipal,
    billing: Annotated[ServiceClient, Depends(billing_client)],
) -> list[dict]:
    return await InvoiceService(billing).list_invoices(principal.subject)
