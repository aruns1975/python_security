"""Typed client for the Another Called application (service id ANOTHER_CALLED_APP,
auth type APP_CREDENTIALS).

The application ID and secret key are attached by `AppCredentialsInterceptor` inside
`SecureHttpClient`; this class never handles them.
"""

from pydantic import TypeAdapter

from clients.models import InventoryItem
from clients.validation import parse_response
from security.exceptions import OutboundServiceError
from security.outbound.service_client import ServiceClient

_ITEMS = TypeAdapter(list[InventoryItem])
_ITEM = TypeAdapter(InventoryItem)


class AnotherCalledAppClient:
    SERVICE_ID = "ANOTHER_CALLED_APP"

    def __init__(self, client: ServiceClient) -> None:
        if client.service_id != self.SERVICE_ID:
            raise ValueError(f"AnotherCalledAppClient must be bound to {self.SERVICE_ID}")
        self._client = client

    async def list_inventory(self) -> list[InventoryItem]:
        response = await self._client.get("/api/v1/inventory")
        return parse_response(self.SERVICE_ID, response, _ITEMS)

    async def get_item(self, sku: str) -> InventoryItem | None:
        """Return the item, or None when the downstream reports 404."""
        try:
            response = await self._client.get(f"/api/v1/inventory/{sku}")
        except OutboundServiceError as exc:
            if exc.status_code == 404:
                return None
            raise
        return parse_response(self.SERVICE_ID, response, _ITEM)
