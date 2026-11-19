"""In-memory sample data for the Another Called application.

A real service would query a database here, filtering by the caller's tenant in the query
itself (inbound-security.md §7.5). The sample data has no tenants.
"""

from pydantic import BaseModel


class InventoryItem(BaseModel):
    sku: str
    name: str
    quantity: int
    warehouse: str


_ITEMS: dict[str, InventoryItem] = {
    i.sku: i
    for i in (
        InventoryItem(sku="SKU-100", name="Pallet jack", quantity=12, warehouse="CHI-1"),
        InventoryItem(sku="SKU-200", name="Shrink wrap roll", quantity=480, warehouse="DAL-2"),
        InventoryItem(sku="SKU-300", name="Cold-chain sensor", quantity=75, warehouse="CHI-1"),
    )
}


class InventoryRepository:
    async def list_items(self) -> list[InventoryItem]:
        return list(_ITEMS.values())

    async def find_item(self, sku: str) -> InventoryItem | None:
        return _ITEMS.get(sku)
