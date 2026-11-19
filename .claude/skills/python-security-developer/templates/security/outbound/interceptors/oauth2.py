import httpx

from security.outbound.interceptors.base import AuthenticationInterceptor
from security.outbound.request_context import RequestContext
from security.outbound.service_registry import AuthType
from security.outbound.token_provider import TokenProvider


class OAuth2Interceptor(AuthenticationInterceptor):
    auth_type = AuthType.OAUTH2_CLIENT_CREDENTIALS

    def __init__(self, token_provider: TokenProvider) -> None:
        self._tokens = token_provider

    async def intercept(self, context: RequestContext) -> None:
        token = await self._tokens.get_access_token(context.service)
        context.attributes["oauth2_token"] = token
        context.request.headers["Authorization"] = f"Bearer {token}"

    async def on_unauthorized(self, context: RequestContext, response: httpx.Response) -> bool:
        token = context.attributes.get("oauth2_token")
        if token:
            self._tokens.invalidate(context.service, token)
        return True
