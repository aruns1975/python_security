"""Framework-level tests adapted from the reference suite (testing.md §3, service layer):
decorators, policies, context propagation and principal immutability."""

import asyncio

import pytest

from security.exceptions import AuthenticationException, AuthorizationException
from security.inbound.context_holder import SecurityContextHolder, create_detached_task
from security.inbound.decorators import post_authorize, pre_authorize, secured
from security.inbound.policies import has_authority, has_role
from security.inbound.principal import SecurityContext, SecurityPrincipal

ADMIN = SecurityPrincipal("u1", "TEST", authorities=frozenset({"ORDER_READ"}), roles=frozenset({"ADMIN"}))
USER = SecurityPrincipal("u2", "TEST", authorities=frozenset(), roles=frozenset({"USER"}))


class SampleService:
    @pre_authorize(has_authority("ORDER_READ"))
    async def get_items(self) -> list[str]:
        return ["o1"]

    @secured("ADMIN")
    def delete(self) -> bool:
        return True

    @post_authorize(lambda principal, item: item["owner"] == principal.subject)
    async def get_item(self, owner: str) -> dict[str, str]:
        return {"owner": owner}


async def test_pre_authorize_and_secured() -> None:
    svc = SampleService()
    with pytest.raises(AuthenticationException):
        await svc.get_items()
    with SecurityContextHolder.use(SecurityContext(ADMIN)):
        assert await svc.get_items() == ["o1"] and svc.delete() is True
    with SecurityContextHolder.use(SecurityContext(USER)):
        with pytest.raises(AuthorizationException):
            await svc.get_items()
        with pytest.raises(AuthorizationException):
            svc.delete()


async def test_post_authorize() -> None:
    svc = SampleService()
    with SecurityContextHolder.use(SecurityContext(ADMIN)):
        assert await svc.get_item("u1") == {"owner": "u1"}
        with pytest.raises(AuthorizationException):
            await svc.get_item("someone-else")


def test_policy_composition() -> None:
    policy = has_role("ADMIN") | has_authority("ORDER_DELETE")
    assert policy(ADMIN) and not policy(USER) and (~policy)(USER)


def test_decorators_reject_generators() -> None:
    with pytest.raises(TypeError, match="do not support generator functions"):

        @pre_authorize(has_role("ADMIN"))
        async def stream():
            yield 1


async def test_detached_task_does_not_inherit_identity() -> None:
    async def who() -> SecurityPrincipal | None:
        return SecurityContextHolder.get_principal()

    with SecurityContextHolder.use(SecurityContext(ADMIN)):
        assert await asyncio.create_task(who()) is ADMIN
        assert await create_detached_task(who()) is None
        assert await asyncio.to_thread(SecurityContextHolder.get_principal) is ADMIN


def test_principal_is_immutable() -> None:
    claims = {"a": 1}
    p = SecurityPrincipal("s", "T", claims=claims)
    claims["a"] = 2
    assert p.claims["a"] == 1
    with pytest.raises(TypeError):
        p.claims["a"] = 3  # type: ignore[index]
    with pytest.raises(AttributeError):
        p.subject = "x"  # type: ignore[misc]
    assert hash(p)
