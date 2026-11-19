"""Inbound security settings and wiring for the Called application.

Adapted from the reference `security/configuration.py`: this service only accepts API keys,
so the JWT/Basic settings and the outbound stack are omitted. Every value comes from the
environment (pydantic-settings) and has no default, so a missing pepper or key list stops
startup instead of silently disabling authentication (fail closed).
"""

from collections.abc import Sequence

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from security.inbound.api_key_provider import ApiKeyAuthenticationProvider, ApiKeyRecord, InMemoryApiKeyStore
from security.inbound.authentication_manager import AuthenticationManager
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.exception_handlers import install_security_exception_handlers
from security.inbound.middleware import SecurityMiddleware


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
