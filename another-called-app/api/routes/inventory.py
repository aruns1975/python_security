"""Inventory endpoints. The whole router requires INVENTORY_READ (router-level dependency)."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path

from security.inbound.dependencies import require_authority
from services.inventory_repository import InventoryItem, InventoryRepository

router = APIRouter(
    prefix="/api/v1/inventory",
    tags=["inventory"],
    dependencies=[Depends(require_authority("INVENTORY_READ"))],
)

SKU = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,64}$")]


def get_repository() -> InventoryRepository:
    return InventoryRepository()


@router.get("")
async def list_inventory(
    repository: Annotated[InventoryRepository, Depends(get_repository)],
) -> list[InventoryItem]:
    return await repository.list_items()


@router.get("/{sku}")
async def get_inventory_item(
    sku: SKU,
    repository: Annotated[InventoryRepository, Depends(get_repository)],
) -> InventoryItem:
    item = await repository.find_item(sku)
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item
