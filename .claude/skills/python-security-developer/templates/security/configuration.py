import http.cookiejar
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import FastAPI
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from security.inbound.authentication_manager import AuthenticationManager
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.exception_handlers import install_security_exception_handlers
from security.inbound.middleware import SecurityMiddleware
from security.outbound.credential_provider import EnvSecretStore, SecretStore
from security.outbound.interceptor_manager import InterceptorManager
from security.outbound.interceptors.api_key import ApiKeyInterceptor
from security.outbound.interceptors.base import RequestInterceptor
from security.outbound.interceptors.basic_auth import BasicAuthInterceptor
from security.outbound.interceptors.correlation_id import CorrelationIdInterceptor
from security.outbound.interceptors.oauth2 import OAuth2Interceptor
from security.outbound.secure_http_client import SecureHttpClient
from security.outbound.service_client import ServiceClient
from security.outbound.service_registry import ServiceConfig, ServiceRegistry
from security.outbound.token_provider import ClientCredentialsTokenProvider


class InboundSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECURITY_INBOUND_", env_nested_delimiter="__", extra="ignore")

    jwt_enabled: bool = True
    jwt_issuer: str = ""
    jwt_audience: str = ""
    jwt_jwks_url: str | None = None
    jwt_algorithms: tuple[str, ...] = ("RS256",)
    api_key_enabled: bool = False
    api_key_pepper: SecretStr | None = None
    basic_enabled: bool = False
    public_paths: tuple[str, ...] = ("/health", "/docs", "/openapi.json")


class OutboundSettings(BaseSettings):
    """Example env: SECURITY_OUTBOUND_SERVICES='{"BILLING": {"service_id": "BILLING", ...}}'"""

    model_config = SettingsConfigDict(env_prefix="SECURITY_OUTBOUND_", extra="ignore")

    services: dict[str, ServiceConfig] = Field(default_factory=dict)


class _RejectAllCookiesPolicy(http.cookiejar.DefaultCookiePolicy):
    """Service-to-service calls are stateless: a cookie set by one downstream must never be
    replayed to another service or on behalf of another user. (Passing a jar via
    `httpx.AsyncClient(cookies=...)` does not work: httpx copies cookies into a new jar.)"""

    def set_ok(self, cookie: http.cookiejar.Cookie, request: object) -> bool:
        return False

    def return_ok(self, cookie: http.cookiejar.Cookie, request: object) -> bool:
        return False


@dataclass
class OutboundSecurity:
    http_client: httpx.AsyncClient
    secure_client: SecureHttpClient

    def client_for(self, service_id: str) -> ServiceClient:
        return ServiceClient(self.secure_client, service_id)


def configure_inbound_security(
    app: FastAPI, providers: Sequence[AuthenticationProvider], public_paths: Sequence[str]
) -> None:
    """Register the security middleware and exception handlers. Add CORSMiddleware
    AFTER this call so it wraps (runs before) security and answers preflights."""
    install_security_exception_handlers(app)
    app.add_middleware(
        SecurityMiddleware,
        authentication_manager=AuthenticationManager(providers),
        public_paths=public_paths,
    )


@asynccontextmanager
async def outbound_security(
    settings: OutboundSettings,
    *,
    secrets: SecretStore | None = None,
    extra_interceptors: Sequence[RequestInterceptor] = (),
    transport: httpx.AsyncBaseTransport | None = None,
) -> AsyncIterator[OutboundSecurity]:
    """Build the shared outbound stack; use inside the FastAPI lifespan."""
    secrets = secrets or EnvSecretStore()
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(10.0, connect=3.0),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        trust_env=False,  # ignore HTTP(S)_PROXY / .netrc: credentials go only where configured
        transport=transport,
    ) as http_client:
        http_client.cookies.jar.set_policy(_RejectAllCookiesPolicy())
        registry = ServiceRegistry(settings.services)
        interceptors = InterceptorManager(
            interceptors=[CorrelationIdInterceptor(), *extra_interceptors],
            auth_interceptors=[
                ApiKeyInterceptor(secrets),
                BasicAuthInterceptor(secrets),
                OAuth2Interceptor(ClientCredentialsTokenProvider(http_client, secrets)),
            ],
        )
        yield OutboundSecurity(http_client, SecureHttpClient(http_client, registry, interceptors))
