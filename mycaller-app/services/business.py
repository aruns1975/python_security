"""Service layer. Methods are protected with `@pre_authorize` (inbound-security.md §7.3), so
the checks hold for any entry point (HTTP, consumers, jobs), not only for the routes, which
also carry `require_authority` dependencies (defence in depth).
"""

import asyncio

from pydantic import BaseModel

from clients.another_called_app_client import AnotherCalledAppClient
from clients.called_app_client import CalledAppClient
from clients.models import InventoryItem, Order
from security.inbound.decorators import pre_authorize
from security.inbound.policies import has_authority


class OrderService:
    def __init__(self, called_app: CalledAppClient) -> None:
        self._called_app = called_app

    @pre_authorize(has_authority("ORDER_READ"))
    async def list_orders(self) -> list[Order]:
        return await self._called_app.list_orders()

    @pre_authorize(has_authority("ORDER_READ"))
    async def get_order(self, order_id: str) -> Order | None:
        return await self._called_app.get_order(order_id)


class InventoryService:
    def __init__(self, another_called_app: AnotherCalledAppClient) -> None:
        self._another_called_app = another_called_app

    @pre_authorize(has_authority("INVENTORY_READ"))
    async def list_inventory(self) -> list[InventoryItem]:
        return await self._another_called_app.list_inventory()

    @pre_authorize(has_authority("INVENTORY_READ"))
    async def get_item(self, sku: str) -> InventoryItem | None:
        return await self._another_called_app.get_item(sku)


class Dashboard(BaseModel):
    orders: list[Order]
    inventory: list[InventoryItem]
    order_count: int
    order_total: float
    inventory_units: int


class DashboardService:
    def __init__(self, orders: OrderService, inventory: InventoryService) -> None:
        self._orders = orders
        self._inventory = inventory

    @pre_authorize(has_authority("DASHBOARD_READ"))
    async def get_dashboard(self) -> Dashboard:
        # gather() copies the current context into each task, so the nested @pre_authorize
        # checks see the same principal: DASHBOARD_READ, ORDER_READ and INVENTORY_READ are all
        # required. Each downstream call gets its own service's credentials only.
        orders, inventory = await asyncio.gather(self._orders.list_orders(), self._inventory.list_inventory())
        return Dashboard(
            orders=orders,
            inventory=inventory,
            order_count=len(orders),
            order_total=round(sum(o.total for o in orders), 2),
            inventory_units=sum(i.quantity for i in inventory),
        )
