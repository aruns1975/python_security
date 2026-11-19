"""Inbound and outbound security settings and wiring for the MyCaller application.

Adapted from the reference `security/configuration.py`:
- inbound accepts only API keys (JWT/Basic settings omitted);
- outbound registers the API key interceptor and the new app-credentials interceptor
  (Basic/OAuth2 are omitted because no registered service uses them; a service configured
  with one of those auth types therefore fails startup in `InterceptorManager.validate`).

Every value comes from the environment (pydantic-settings). Security settings have no
defaults, so missing configuration stops startup instead of disabling security (fail closed).
"""

import http.cookiejar
import urllib.request
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from security.inbound.api_key_provider import ApiKeyAuthenticationProvider, ApiKeyRecord, InMemoryApiKeyStore
from security.inbound.authentication_manager import AuthenticationManager
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.exception_handlers import install_security_exception_handlers
from security.inbound.middleware import SecurityMiddleware
from security.outbound.credential_provider import EnvSecretStore, SecretStore
from security.outbound.interceptor_manager import InterceptorManager
from security.outbound.interceptors.api_key import ApiKeyInterceptor
from security.outbound.interceptors.app_credentials import AppCredentialsInterceptor
from security.outbound.interceptors.base import RequestInterceptor
from security.outbound.interceptors.correlation_id import CorrelationIdInterceptor
from security.outbound.secure_http_client import SecureHttpClient
from security.outbound.service_client import ServiceClient
from security.outbound.service_registry import AuthType, ServiceConfig, ServiceRegistry


class ApiKeyEntry(BaseModel):
    """One stored API key. Holds the peppered HMAC hash, never the raw key."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    key_id: str = Field(min_length=1)  # non-secret identifier, safe to log
    # 64 lowercase hex chars = HMAC-SHA256 digest; rejects a raw key pasted by mistake.
    key_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    subject: str = Field(min_length=1)
    authorities: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    tenant_id: str | None = None
    enabled: bool = True

    def to_record(self) -> ApiKeyRecord:
        return ApiKeyRecord(
            key_id=self.key_id,
            key_hash=self.key_hash,
            subject=self.subject,
            authorities=self.authorities,
            roles=self.roles,
            tenant_id=self.tenant_id,
            enabled=self.enabled,
        )


# FastAPI's interactive API docs. Public so the Swagger UI / ReDoc pages and the OpenAPI spec they
# load can be opened without credentials; the API calls made from "Try it out" still need them.
# Matched exactly (no prefixes), so nothing else under these paths becomes public.
API_DOCS_PATHS = ("/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json")

# The only paths that may ever be served without authentication.
ALLOWED_PUBLIC_PATHS = frozenset({"/health", *API_DOCS_PATHS})


class InboundSettings(BaseSettings):
    """Env: SECURITY_INBOUND_API_KEY_PEPPER, SECURITY_INBOUND_API_KEYS='[{"key_id": ..., "key_hash": ...}]'."""

    model_config = SettingsConfigDict(env_prefix="SECURITY_INBOUND_", extra="ignore")

    # No defaults: missing configuration must fail startup.
    api_key_pepper: SecretStr
    api_keys: tuple[ApiKeyEntry, ...] = Field(min_length=1)
    api_key_header: str = "X-API-Key"
    public_paths: tuple[str, ...] = ("/health", *API_DOCS_PATHS)

    @field_validator("public_paths")
    @classmethod
    def _only_allow_listed_public_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # A typo such as "/" or a prefix like "/api/" would make whole areas anonymous: only
        # exact, allow-listed paths may be configured as public.
        disallowed = [p for p in value if p not in ALLOWED_PUBLIC_PATHS]
        if disallowed:
            raise ValueError(f"public_paths not allowed: {disallowed}; permitted: {sorted(ALLOWED_PUBLIC_PATHS)}")
        return value


def build_providers(settings: InboundSettings) -> list[AuthenticationProvider]:
    """API key is the only accepted mechanism for this service."""
    store = InMemoryApiKeyStore([entry.to_record() for entry in settings.api_keys])
    # Provider enforces a >= 32-byte pepper.
    pepper = settings.api_key_pepper.get_secret_value().encode()
    return [ApiKeyAuthenticationProvider(store, pepper, header_name=settings.api_key_header)]


def configure_inbound_security(
    app: FastAPI,
    providers: Sequence[AuthenticationProvider],
    public_paths: Sequence[str],
    *,
    challenge_scheme: str = "Bearer",
) -> None:
    """Register the security middleware and exception handlers. Add CORSMiddleware
    AFTER this call so it wraps (runs before) security and answers preflights."""
    install_security_exception_handlers(app)
    app.add_middleware(
        SecurityMiddleware,
        authentication_manager=AuthenticationManager(providers),
        public_paths=public_paths,
        challenge_scheme=challenge_scheme,
    )


class OutboundSettings(BaseSettings):
    """Env: SECURITY_OUTBOUND_SERVICES='{"CALLED_APP": {"service_id": "CALLED_APP", ...}}'.

    Holds secret *references* only; the secrets themselves are resolved by the SecretStore
    (env vars `OUTBOUND_<CREDENTIAL_REF>__<KEY>` with the default EnvSecretStore)."""

    model_config = SettingsConfigDict(env_prefix="SECURITY_OUTBOUND_", extra="ignore")

    services: dict[str, ServiceConfig] = Field(default_factory=dict)


# Secret-store keys each auth type needs, per credential_ref (outbound-security.md §3).
REQUIRED_SECRET_KEYS: Mapping[AuthType, tuple[str, ...]] = {
    AuthType.NONE: (),
    AuthType.API_KEY: ("api_key",),
    AuthType.APP_CREDENTIALS: ("application_id", "secret_key"),
}


class _RejectAllCookiesPolicy(http.cookiejar.DefaultCookiePolicy):
    """Service-to-service calls are stateless; never store or send cookies.

    Without this the shared client's cookie jar would replay a Set-Cookie from one
    downstream service to another (same host, different port) and across callers."""

    def set_ok(self, cookie: http.cookiejar.Cookie, request: urllib.request.Request) -> bool:
        return False

    def return_ok(self, cookie: http.cookiejar.Cookie, request: urllib.request.Request) -> bool:
        return False


@dataclass
class OutboundSecurity:
    http_client: httpx.AsyncClient
    secure_client: SecureHttpClient

    def client_for(self, service_id: str) -> ServiceClient:
        return ServiceClient(self.secure_client, service_id)


async def verify_outbound_secrets(services: Mapping[str, ServiceConfig], secrets: SecretStore) -> None:
    """Fail at startup, not on the first request, when a registered service's secrets are
    missing. Errors name the missing variable, never a value."""
    for service in services.values():
        for key in REQUIRED_SECRET_KEYS.get(service.auth_type, ()):
            assert service.credential_ref is not None  # guaranteed by ServiceConfig validation
            await secrets.get_secret(service.credential_ref, key)


@asynccontextmanager
async def outbound_security(
    settings: OutboundSettings,
    *,
    secrets: SecretStore | None = None,
    extra_interceptors: Sequence[RequestInterceptor] = (),
    transport: httpx.AsyncBaseTransport | None = None,
    backoff_base_seconds: float = 0.2,
) -> AsyncIterator[OutboundSecurity]:
    """Build the shared outbound stack; use inside the FastAPI lifespan."""
    secrets = secrets or EnvSecretStore()
    await verify_outbound_secrets(settings.services, secrets)
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(10.0, connect=3.0),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        transport=transport,
        # Ignore HTTP(S)_PROXY / ALL_PROXY / .netrc from the environment: credentials (sent over
        # plain http locally) must never be routed through a proxy or pick up .netrc secrets.
        trust_env=False,
    ) as http_client:
        # Set the policy on the client's own jar: httpx.Cookies(jar) copies cookies into a
        # fresh jar and drops the policy, so passing a pre-built jar does not work.
        http_client.cookies.jar.set_policy(_RejectAllCookiesPolicy())
        registry = ServiceRegistry(settings.services)
        interceptors = InterceptorManager(
            interceptors=[CorrelationIdInterceptor(), *extra_interceptors],
            auth_interceptors=[
                ApiKeyInterceptor(secrets),
                AppCredentialsInterceptor(secrets),
            ],
        )
        yield OutboundSecurity(
            http_client,
            SecureHttpClient(http_client, registry, interceptors, backoff_base_seconds=backoff_base_seconds),
        )
