"""Service-layer @pre_authorize tests (testing.md §5: no context -> AuthenticationException,
denied -> AuthorizationException, allowed -> result), without HTTP."""

import pytest

from clients.models import InventoryItem, Order
from security.exceptions import AuthenticationException, AuthorizationException
from security.inbound.context_holder import SecurityContextHolder
from security.inbound.principal import SecurityContext, SecurityPrincipal
from services.business import DashboardService, InventoryService, OrderService

ORDER = Order(id="O1", customer="Acme", status="NEW", total=2.5)
ITEM = InventoryItem(sku="S1", name="Box", quantity=4, warehouse="W1")


class FakeCalledApp:
    async def list_orders(self) -> list[Order]:
        return [ORDER]

    async def get_order(self, order_id: str) -> Order | None:
        return ORDER if order_id == "O1" else None


class FakeAnotherCalledApp:
    async def list_inventory(self) -> list[InventoryItem]:
        return [ITEM]

    async def get_item(self, sku: str) -> InventoryItem | None:
        return ITEM if sku == "S1" else None


def principal(*authorities: str) -> SecurityContext:
    return SecurityContext(SecurityPrincipal("client:t", "API_KEY", authorities=frozenset(authorities)))


@pytest.fixture
def services() -> tuple[OrderService, InventoryService, DashboardService]:
    orders = OrderService(FakeCalledApp())  # type: ignore[arg-type]
    inventory = InventoryService(FakeAnotherCalledApp())  # type: ignore[arg-type]
    return orders, inventory, DashboardService(orders, inventory)


async def test_no_context_raises_authentication(services) -> None:
    orders, inventory, dashboard = services
    for call in (orders.list_orders(), inventory.list_inventory(), dashboard.get_dashboard()):
        with pytest.raises(AuthenticationException):
            await call


async def test_denied_raises_authorization(services) -> None:
    orders, inventory, dashboard = services
    with SecurityContextHolder.use(principal("INVENTORY_READ")):
        with pytest.raises(AuthorizationException):
            await orders.list_orders()
    with SecurityContextHolder.use(principal("ORDER_READ")):
        with pytest.raises(AuthorizationException):
            await inventory.get_item("S1")
    # DASHBOARD_READ alone is not enough: the nested calls are also protected.
    with SecurityContextHolder.use(principal("DASHBOARD_READ", "ORDER_READ")):
        with pytest.raises(AuthorizationException):
            await dashboard.get_dashboard()


async def test_allowed_returns_result(services) -> None:
    orders, inventory, dashboard = services
    with SecurityContextHolder.use(principal("ORDER_READ", "INVENTORY_READ", "DASHBOARD_READ")):
        assert await orders.get_order("O1") == ORDER
        assert await inventory.list_inventory() == [ITEM]
        result = await dashboard.get_dashboard()
    assert result.order_count == 1 and result.inventory_units == 4 and result.order_total == 2.5
