"""Dashboard endpoint: combines both downstream services concurrently."""

from typing import Annotated

from fastapi import APIRouter, Depends

from api.dependencies import get_dashboard_service
from security.inbound.dependencies import require_authority
from services.business import Dashboard, DashboardService

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("", dependencies=[Depends(require_authority("DASHBOARD_READ", "ORDER_READ", "INVENTORY_READ"))])
async def get_dashboard(service: Annotated[DashboardService, Depends(get_dashboard_service)]) -> Dashboard:
    return await service.get_dashboard()
