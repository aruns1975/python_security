import logging
from collections.abc import Iterable

from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from security.exceptions import AuthenticationException
from security.inbound.authentication_manager import AuthenticationManager
from security.inbound.context_holder import SecurityContextHolder
from security.inbound.principal import SecurityContext

logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """Pure ASGI authentication middleware (the SecurityFilterChain equivalent).

    Runs outside FastAPI's exception handlers, so it builds 401 responses itself.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        authentication_manager: AuthenticationManager,
        public_paths: Iterable[str] = (),
    ) -> None:
        self.app = app
        self._manager = authentication_manager
        # "/health" matches exactly; "/docs/" matches the prefix.
        paths = tuple(public_paths)
        self._public_exact = frozenset(p for p in paths if not p.endswith("/"))
        self._public_prefixes = tuple(p for p in paths if p.endswith("/"))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        try:
            principal = await self._manager.authenticate(HTTPConnection(scope))
        except AuthenticationException as exc:
            # Invalid credentials are rejected even on public paths.
            logger.info("Authentication failed", extra={"path": scope.get("path")})
            await self._reject(scope, receive, send, exc)
            return

        if principal is None and not self._is_public(scope["path"]):
            await self._reject(scope, receive, send, AuthenticationException())
            return

        token = SecurityContextHolder.set_context(SecurityContext(principal))
        try:
            await self.app(scope, receive, send)
        finally:
            SecurityContextHolder.reset_context(token)

    def _is_public(self, path: str) -> bool:
        return path in self._public_exact or path.startswith(self._public_prefixes)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, exc: AuthenticationException) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        response = JSONResponse(
            {"error": "unauthorized", "detail": str(exc)},
            status_code=401,
            headers={"WWW-Authenticate": exc.scheme},
        )
        await response(scope, receive, send)
