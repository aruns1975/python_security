"""Maps downstream failures to a clean 502.

`OutboundServiceError` already carries no URL query, headers or body; the client-facing
response goes further and omits the service id and downstream status too. Those are logged
server-side for operators.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from security.exceptions import OutboundServiceError

logger = logging.getLogger(__name__)


async def _outbound_service_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, OutboundServiceError)
    logger.warning(
        "Downstream call failed",
        extra={"service_id": exc.service_id, "status": exc.status_code, "path": request.url.path},
    )
    return JSONResponse({"error": "bad_gateway", "detail": "Upstream service error"}, status_code=502)


def install_outbound_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(OutboundServiceError, _outbound_service_error_handler)
