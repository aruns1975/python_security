"""Order endpoints. Every route carries an explicit authority dependency."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path

from security.inbound.dependencies import require_authority
from services.order_repository import Order, OrderRepository

router = APIRouter(prefix="/api/v1/orders", tags=["orders"])

ORDER_ID = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,64}$")]


def get_repository() -> OrderRepository:
    return OrderRepository()


@router.get("", dependencies=[Depends(require_authority("ORDER_READ"))])
async def list_orders(
    repository: Annotated[OrderRepository, Depends(get_repository)],
) -> list[Order]:
    return await repository.list_orders()


@router.get("/{order_id}", dependencies=[Depends(require_authority("ORDER_READ"))])
async def get_order(
    order_id: ORDER_ID,
    repository: Annotated[OrderRepository, Depends(get_repository)],
) -> Order:
    order = await repository.find_order(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return order
