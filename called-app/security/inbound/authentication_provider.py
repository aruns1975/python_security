from abc import ABC, abstractmethod
from typing import ClassVar

from starlette.requests import HTTPConnection

from security.inbound.principal import SecurityPrincipal


class AuthenticationProvider(ABC):
    """One authentication mechanism. Providers must not read the request body."""

    name: ClassVar[str]

    @abstractmethod
    def supports(self, connection: HTTPConnection) -> bool:
        """Cheap check: are this provider's credentials present? No validation here."""

    @abstractmethod
    async def authenticate(self, connection: HTTPConnection) -> SecurityPrincipal:
        """Validate credentials and return a principal, or raise AuthenticationException."""


def parse_authorization(connection: HTTPConnection, scheme: str) -> str | None:
    """Return the credentials part of `Authorization: <scheme> <credentials>`."""
    header = connection.headers.get("authorization")
    if not header:
        return None
    found_scheme, _, credentials = header.partition(" ")
    if found_scheme.lower() != scheme.lower():
        return None
    return credentials.strip()
