from collections.abc import Callable

from security.inbound.principal import SecurityPrincipal


class Policy:
    """Composable authorization rule: `has_role("ADMIN") | has_authority("ORDER_DELETE")`."""

    __slots__ = ("_check", "description")

    def __init__(self, check: Callable[[SecurityPrincipal], bool], description: str) -> None:
        self._check = check
        self.description = description

    def __call__(self, principal: SecurityPrincipal) -> bool:
        return bool(self._check(principal))

    def __and__(self, other: "Policy") -> "Policy":
        return Policy(lambda p: self(p) and other(p), f"({self.description} and {other.description})")

    def __or__(self, other: "Policy") -> "Policy":
        return Policy(lambda p: self(p) or other(p), f"({self.description} or {other.description})")

    def __invert__(self) -> "Policy":
        return Policy(lambda p: not self(p), f"not {self.description}")

    def __repr__(self) -> str:
        return f"Policy({self.description})"


def is_authenticated() -> Policy:
    return Policy(lambda p: True, "is_authenticated")


def has_authority(authority: str) -> Policy:
    return Policy(lambda p: authority in p.authorities, f"has_authority({authority!r})")


def has_any_authority(*authorities: str) -> Policy:
    required = frozenset(authorities)
    return Policy(lambda p: bool(required & p.authorities), f"has_any_authority{authorities!r}")


def has_all_authorities(*authorities: str) -> Policy:
    required = frozenset(authorities)
    return Policy(lambda p: required <= p.authorities, f"has_all_authorities{authorities!r}")


def has_role(role: str) -> Policy:
    return Policy(lambda p: role in p.roles, f"has_role({role!r})")


def has_any_role(*roles: str) -> Policy:
    required = frozenset(roles)
    return Policy(lambda p: bool(required & p.roles), f"has_any_role{roles!r}")


def belongs_to_tenant(tenant_id: str) -> Policy:
    return Policy(lambda p: p.tenant_id is not None and p.tenant_id == tenant_id, f"belongs_to_tenant({tenant_id!r})")
