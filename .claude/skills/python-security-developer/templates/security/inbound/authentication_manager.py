import logging
from collections.abc import Sequence

from starlette.requests import HTTPConnection

from security.exceptions import AuthenticationException
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.principal import SecurityPrincipal

logger = logging.getLogger(__name__)


class AuthenticationManager:
    """Selects exactly one provider for a request and delegates to it."""

    def __init__(self, providers: Sequence[AuthenticationProvider]) -> None:
        names = [p.name for p in providers]
        if len(names) != len(set(names)):
            raise ValueError(f"Duplicate authentication providers: {names}")
        self._providers = tuple(providers)

    async def authenticate(self, connection: HTTPConnection) -> SecurityPrincipal | None:
        """Return a principal, None when no credentials were presented (anonymous),
        or raise AuthenticationException for invalid or ambiguous credentials."""
        matching = [p for p in self._providers if p.supports(connection)]
        if not matching:
            return None
        if len(matching) > 1:
            # Deterministic policy: multiple credential types on one request are rejected.
            raise AuthenticationException("Ambiguous authentication: multiple credentials supplied")
        provider = matching[0]
        principal = await provider.authenticate(connection)
        logger.info("Authentication successful", extra={"auth_type": provider.name, "subject": principal.subject})
        return principal
