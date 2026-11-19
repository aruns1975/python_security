"""In-memory sample data for the Called application.

A real service would query a database here, filtering by the caller's tenant in the query
itself (inbound-security.md §7.5). The sample data has no tenants.
"""

from pydantic import BaseModel


class Order(BaseModel):
    id: str
    customer: str
    status: str
    total: float


_ORDERS: dict[str, Order] = {
    o.id: o
    for o in (
        Order(id="ORD-1001", customer="Acme Corp", status="SHIPPED", total=1250.00),
        Order(id="ORD-1002", customer="Globex", status="PENDING", total=310.50),
        Order(id="ORD-1003", customer="Initech", status="DELIVERED", total=87.25),
    )
}


class OrderRepository:
    async def list_orders(self) -> list[Order]:
        return list(_ORDERS.values())

    async def find_order(self, order_id: str) -> Order | None:
        return _ORDERS.get(order_id)
