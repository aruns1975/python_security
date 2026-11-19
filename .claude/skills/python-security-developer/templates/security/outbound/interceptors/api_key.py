from security.outbound.credential_provider import SecretStore
from security.outbound.interceptors.base import AuthenticationInterceptor
from security.outbound.request_context import RequestContext
from security.outbound.service_registry import AuthType


class ApiKeyInterceptor(AuthenticationInterceptor):
    auth_type = AuthType.API_KEY

    def __init__(self, secrets: SecretStore) -> None:
        self._secrets = secrets

    async def intercept(self, context: RequestContext) -> None:
        service = context.service
        assert service.credential_ref is not None  # guaranteed by ServiceConfig validation
        api_key = await self._secrets.get_secret(service.credential_ref, "api_key")
        context.request.headers[service.api_key_header] = api_key
