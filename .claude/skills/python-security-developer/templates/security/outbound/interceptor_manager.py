from collections.abc import Iterable

from security.exceptions import OutboundSecurityException
from security.outbound.interceptors.base import AuthenticationInterceptor, NoAuthInterceptor, RequestInterceptor
from security.outbound.request_context import RequestContext
from security.outbound.service_registry import AuthType, ServiceRegistry


class InterceptorManager:
    """Runs general interceptors (ordered, many) then exactly one authentication interceptor."""

    def __init__(
        self,
        interceptors: Iterable[RequestInterceptor] = (),
        auth_interceptors: Iterable[AuthenticationInterceptor] = (),
    ) -> None:
        self._interceptors = sorted(interceptors, key=lambda i: i.order)
        self._auth: dict[AuthType, AuthenticationInterceptor] = {AuthType.NONE: NoAuthInterceptor()}
        for interceptor in auth_interceptors:
            if interceptor.auth_type in self._auth and interceptor.auth_type is not AuthType.NONE:
                raise OutboundSecurityException(f"Ambiguous: two authentication interceptors for {interceptor.auth_type}")
            self._auth[interceptor.auth_type] = interceptor

    def validate(self, registry: ServiceRegistry) -> None:
        """Fail fast at startup if any registered service has no authentication strategy."""
        missing = {s.service_id: s.auth_type for s in registry.all() if s.auth_type not in self._auth}
        if missing:
            raise OutboundSecurityException(f"No authentication interceptor for: {missing}")

    def auth_for(self, context: RequestContext) -> AuthenticationInterceptor:
        try:
            return self._auth[context.service.auth_type]
        except KeyError:
            raise OutboundSecurityException(f"No authentication interceptor for {context.service.auth_type}") from None

    async def execute(self, context: RequestContext) -> AuthenticationInterceptor:
        for interceptor in self._interceptors:
            if interceptor.supports(context):
                await interceptor.intercept(context)
        auth = self.auth_for(context)
        await auth.intercept(context)
        return auth
