from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from security.exceptions import AuthenticationException, AuthorizationException


async def _authentication_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AuthenticationException)
    return JSONResponse(
        {"error": "unauthorized", "detail": str(exc)},
        status_code=401,
        headers={"WWW-Authenticate": exc.scheme},
    )


async def _authorization_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse({"error": "forbidden", "detail": "Access denied"}, status_code=403)


def install_security_exception_handlers(app: FastAPI) -> None:
    """Map security exceptions raised in endpoints, dependencies and services to 401/403."""
    app.add_exception_handler(AuthenticationException, _authentication_handler)
    app.add_exception_handler(AuthorizationException, _authorization_handler)
