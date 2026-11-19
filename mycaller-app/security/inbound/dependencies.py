from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends
from fastapi.security import APIKeyHeader

from security.inbound.authorization import authorize
from security.inbound.context_holder import SecurityContextHolder
from security.inbound.policies import Policy, has_all_authorities, has_any_role
from security.inbound.principal import SecurityPrincipal

# Declared only so OpenAPI / Swagger shows the security schemes. Authentication itself is
# done by SecurityMiddleware; auto_error=False keeps these schemes from enforcing anything.
_api_key_scheme = APIKeyHeader(name="X-API-Key", scheme_name="ApiKey", auto_error=False)


# Dependencies are async on purpose: sync dependencies run in a worker thread.
async def get_current_principal(
    _api_key: Annotated[object, Depends(_api_key_scheme)] = None,
) -> SecurityPrincipal:
    return SecurityContextHolder.require_principal()


async def get_optional_principal() -> SecurityPrincipal | None:
    return SecurityContextHolder.get_principal()


CurrentPrincipal = Annotated[SecurityPrincipal, Depends(get_current_principal)]
OptionalPrincipal = Annotated[SecurityPrincipal | None, Depends(get_optional_principal)]


def require(policy: Policy) -> Callable[..., Awaitable[SecurityPrincipal]]:
    """Endpoint guard: `Depends(require(has_role("ADMIN")))` or in `dependencies=[...]`."""

    async def dependency(_: CurrentPrincipal) -> SecurityPrincipal:
        return authorize(policy)

    return dependency


def require_authority(*authorities: str) -> Callable[..., Awaitable[SecurityPrincipal]]:
    """All listed authorities are required."""
    return require(has_all_authorities(*authorities))


def require_role(*roles: str) -> Callable[..., Awaitable[SecurityPrincipal]]:
    """Any listed role is sufficient."""
    return require(has_any_role(*roles))
