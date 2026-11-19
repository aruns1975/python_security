"""FastAPI dependencies exposing the service layer. Typed clients are built once in the
lifespan (configuration-and-wiring.md §4) and read from `app.state`; tests can override
these with `app.dependency_overrides`."""

from fastapi import Request

from clients.another_called_app_client import AnotherCalledAppClient
from clients.called_app_client import CalledAppClient
from services.business import DashboardService, InventoryService, OrderService


def get_order_service(request: Request) -> OrderService:
    client: CalledAppClient = request.app.state.called_app
    return OrderService(client)


def get_inventory_service(request: Request) -> InventoryService:
    client: AnotherCalledAppClient = request.app.state.another_called_app
    return InventoryService(client)


def get_dashboard_service(request: Request) -> DashboardService:
    return DashboardService(get_order_service(request), get_inventory_service(request))
