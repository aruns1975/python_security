from abc import ABC, abstractmethod
from typing import ClassVar

import httpx

from security.outbound.request_context import RequestContext
from security.outbound.service_registry import AuthType


class RequestInterceptor(ABC):
    """Non-authentication concern (correlation id, tracing, headers). Many may apply.

    Interceptors run BEFORE authentication, so they never see credentials."""

    order: ClassVar[int] = 0

    def supports(self, context: RequestContext) -> bool:
        return True

    @abstractmethod
    async def intercept(self, context: RequestContext) -> None: ...


class AuthenticationInterceptor(ABC):
    """Exactly one per AuthType; selected by the service's configured auth_type,
    never by hard-coded service ids."""

    auth_type: ClassVar[AuthType]

    @abstractmethod
    async def intercept(self, context: RequestContext) -> None: ...

    async def on_unauthorized(self, context: RequestContext, response: httpx.Response) -> bool:
        """Called on a 401. Return True if credentials were refreshed and one retry is worthwhile."""
        return False


class NoAuthInterceptor(AuthenticationInterceptor):
    auth_type = AuthType.NONE

    async def intercept(self, context: RequestContext) -> None:
        return None
