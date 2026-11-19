import base64

from security.outbound.credential_provider import SecretStore
from security.outbound.interceptors.base import AuthenticationInterceptor
from security.outbound.request_context import RequestContext
from security.outbound.service_registry import AuthType


def basic_auth_header(username: str, password: str) -> str:
    # Same encoding as httpx.BasicAuth (RFC 7617, UTF-8).
    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return f"Basic {token}"


class BasicAuthInterceptor(AuthenticationInterceptor):
    auth_type = AuthType.BASIC

    def __init__(self, secrets: SecretStore) -> None:
        self._secrets = secrets

    async def intercept(self, context: RequestContext) -> None:
        ref = context.service.credential_ref
        assert ref is not None
        username = await self._secrets.get_secret(ref, "username")
        password = await self._secrets.get_secret(ref, "password")
        context.request.headers["Authorization"] = basic_auth_header(username, password)
