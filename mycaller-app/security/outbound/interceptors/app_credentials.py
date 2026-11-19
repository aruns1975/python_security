from security.outbound.credential_provider import SecretStore
from security.outbound.interceptors.base import AuthenticationInterceptor
from security.outbound.request_context import RequestContext
from security.outbound.service_registry import AuthType


class AppCredentialsInterceptor(AuthenticationInterceptor):
    """Sends application ID + secret key headers (AuthType.APP_CREDENTIALS).

    Secret-store keys per credential_ref: `application_id`, `secret_key`."""

    auth_type = AuthType.APP_CREDENTIALS

    def __init__(self, secrets: SecretStore) -> None:
        self._secrets = secrets

    async def intercept(self, context: RequestContext) -> None:
        service = context.service
        assert service.credential_ref is not None  # guaranteed by ServiceConfig validation
        application_id = await self._secrets.get_secret(service.credential_ref, "application_id")
        secret_key = await self._secrets.get_secret(service.credential_ref, "secret_key")
        context.request.headers[service.application_id_header] = application_id
        context.request.headers[service.secret_key_header] = secret_key
