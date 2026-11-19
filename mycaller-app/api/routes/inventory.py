"""Inventory endpoints (data from ANOTHER_CALLED_APP). Each route carries an explicit authority dependency."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path

from api.dependencies import get_inventory_service
from clients.models import InventoryItem
from security.inbound.dependencies import require_authority
from services.business import InventoryService

router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])

# Strict pattern: the value is interpolated into a downstream path.
SKU = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,64}$")]


@router.get("", dependencies=[Depends(require_authority("INVENTORY_READ"))])
async def list_inventory(
    service: Annotated[InventoryService, Depends(get_inventory_service)],
) -> list[InventoryItem]:
    return await service.list_inventory()


@router.get("/{sku}", dependencies=[Depends(require_authority("INVENTORY_READ"))])
async def get_inventory_item(
    sku: SKU, service: Annotated[InventoryService, Depends(get_inventory_service)]
) -> InventoryItem:
    item = await service.get_item(sku)
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item
