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
# Each scheme needs its own scheme_name: both default to "APIKeyHeader", and the second would
# silently replace the first in the spec, leaving Swagger's Authorize dialog with one header.
_application_id_scheme = APIKeyHeader(
    name="X-Application-Id", scheme_name="ApplicationId", description="Application ID", auto_error=False
)
_secret_key_scheme = APIKeyHeader(
    name="X-Secret-Key", scheme_name="SecretKey", description="Secret key (send with X-Application-Id)", auto_error=False
)


# Dependencies are async on purpose: sync dependencies run in a worker thread.
async def get_current_principal(
    _application_id: Annotated[object, Depends(_application_id_scheme)] = None,
    _secret_key: Annotated[object, Depends(_secret_key_scheme)] = None,
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
