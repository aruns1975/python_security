"""Order endpoints (data from CALLED_APP). Each route carries an explicit authority dependency."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path

from api.dependencies import get_order_service
from clients.models import Order
from security.inbound.dependencies import require_authority
from services.business import OrderService

router = APIRouter(prefix="/api/v1/orders", tags=["orders"])

# Strict pattern: the value is interpolated into a downstream path.
ORDER_ID = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,64}$")]


@router.get("", dependencies=[Depends(require_authority("ORDER_READ"))])
async def list_orders(service: Annotated[OrderService, Depends(get_order_service)]) -> list[Order]:
    return await service.list_orders()


@router.get("/{order_id}", dependencies=[Depends(require_authority("ORDER_READ"))])
async def get_order(order_id: ORDER_ID, service: Annotated[OrderService, Depends(get_order_service)]) -> Order:
    order = await service.get_order(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return order
