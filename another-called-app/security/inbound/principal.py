from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any


@dataclass(frozen=True, slots=True)
class SecurityPrincipal:
    """Immutable authenticated identity (user or service)."""

    subject: str
    authentication_type: str
    username: str | None = None
    tenant_id: str | None = None
    authorities: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    claims: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def __post_init__(self) -> None:
        # Normalise so callers may pass any iterable / dict without breaking immutability.
        object.__setattr__(self, "authorities", frozenset(self.authorities))
        object.__setattr__(self, "roles", frozenset(self.roles))
        object.__setattr__(self, "claims", MappingProxyType(dict(self.claims)))

    def has_authority(self, authority: str) -> bool:
        return authority in self.authorities

    def has_role(self, role: str) -> bool:
        return role in self.roles


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Security information bound to the current request."""

    principal: SecurityPrincipal | None = None

    @property
    def authenticated(self) -> bool:
        return self.principal is not None

    @property
    def authentication_type(self) -> str | None:
        return self.principal.authentication_type if self.principal else None


ANONYMOUS_CONTEXT = SecurityContext()
