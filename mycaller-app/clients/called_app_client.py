"""Typed client for the Called application (service id CALLED_APP, auth type API_KEY).

Business code depends on this class, never on raw responses or on how CALLED_APP
authenticates: the API key is attached by `ApiKeyInterceptor` inside `SecureHttpClient`.
"""

from pydantic import TypeAdapter

from clients.models import Order
from clients.validation import parse_response
from security.exceptions import OutboundServiceError
from security.outbound.service_client import ServiceClient

_ORDERS = TypeAdapter(list[Order])
_ORDER = TypeAdapter(Order)


class CalledAppClient:
    SERVICE_ID = "CALLED_APP"

    def __init__(self, client: ServiceClient) -> None:
        if client.service_id != self.SERVICE_ID:
            raise ValueError(f"CalledAppClient must be bound to {self.SERVICE_ID}")
        self._client = client

    async def list_orders(self) -> list[Order]:
        response = await self._client.get("/api/v1/orders")
        return parse_response(self.SERVICE_ID, response, _ORDERS)

    async def get_order(self, order_id: str) -> Order | None:
        """Return the order, or None when the downstream reports 404."""
        try:
            response = await self._client.get(f"/api/v1/orders/{order_id}")
        except OutboundServiceError as exc:
            if exc.status_code == 404:
                return None
            raise
        return parse_response(self.SERVICE_ID, response, _ORDER)
