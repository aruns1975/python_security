import asyncio
import contextvars
from collections.abc import Coroutine, Iterator
from contextlib import contextmanager
from typing import Any, TypeVar

from security.exceptions import AuthenticationException
from security.inbound.principal import SecurityContext, SecurityPrincipal

T = TypeVar("T")

# ContextVar, never a global or threading.local(): concurrent requests share threads.
_security_context: contextvars.ContextVar[SecurityContext | None] = contextvars.ContextVar(
    "security_context", default=None
)


class SecurityContextHolder:
    """Spring-style facade over the request-scoped security context."""

    @staticmethod
    def get_context() -> SecurityContext | None:
        return _security_context.get()

    @staticmethod
    def get_principal() -> SecurityPrincipal | None:
        context = _security_context.get()
        return context.principal if context else None

    @staticmethod
    def require_principal() -> SecurityPrincipal:
        principal = SecurityContextHolder.get_principal()
        if principal is None:
            raise AuthenticationException()
        return principal

    @staticmethod
    def set_context(context: SecurityContext | None) -> contextvars.Token[SecurityContext | None]:
        return _security_context.set(context)

    @staticmethod
    def reset_context(token: contextvars.Token[SecurityContext | None]) -> None:
        _security_context.reset(token)

    @staticmethod
    @contextmanager
    def use(context: SecurityContext | None) -> Iterator[None]:
        """Temporarily bind a context (tests, system jobs). Always restored."""
        token = _security_context.set(context)
        try:
            yield
        finally:
            _security_context.reset(token)


def create_detached_task(coro: Coroutine[Any, Any, T], *, name: str | None = None) -> asyncio.Task[T]:
    """Start a task that keeps other context (correlation id, tracing) but does
    NOT inherit the caller's security identity. Use for fire-and-forget work
    that outlives the request."""
    ctx = contextvars.copy_context()
    ctx.run(_security_context.set, None)
    return asyncio.create_task(coro, name=name, context=ctx)
