import functools
import inspect
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar

from security.exceptions import AuthorizationException
from security.inbound.authorization import authorize
from security.inbound.context_holder import SecurityContextHolder
from security.inbound.policies import Policy, has_any_authority, has_any_role
from security.inbound.principal import SecurityPrincipal

P = ParamSpec("P")
R = TypeVar("R")


def _reject_generators(func: Callable[..., Any]) -> None:
    if inspect.isgeneratorfunction(func) or inspect.isasyncgenfunction(func):
        raise TypeError(f"Security decorators do not support generator functions: {func.__qualname__}")


def pre_authorize(policy: Policy) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Check `policy` against the current principal before the call (sync or async)."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        _reject_generators(func)
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                authorize(policy)
                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            authorize(policy)
            return func(*args, **kwargs)

        return sync_wrapper

    return decorator


def secured(*names: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Spring @Secured: allowed when the principal has ANY of the given roles or authorities."""
    if not names:
        raise ValueError("secured() requires at least one role or authority")
    return pre_authorize(has_any_role(*names) | has_any_authority(*names))


def post_authorize(
    check: Callable[[SecurityPrincipal, Any], bool],
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Run the method, then verify `check(principal, result)` before returning it.

    The method runs (side effects happen) even when access is denied, so only use this on
    reads, and still filter queries by tenant/owner; this is defence in depth, not a filter.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        _reject_generators(func)

        def verify(result: Any) -> None:
            if not check(SecurityContextHolder.require_principal(), result):
                raise AuthorizationException()

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                SecurityContextHolder.require_principal()
                result = await func(*args, **kwargs)
                verify(result)
                return result

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            SecurityContextHolder.require_principal()
            result = func(*args, **kwargs)
            verify(result)
            return result

        return sync_wrapper

    return decorator
