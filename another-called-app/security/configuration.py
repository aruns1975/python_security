"""Inbound security settings and wiring for the Another Called application.

Adapted from the reference `security/configuration.py`: this service only accepts
application ID + secret key credentials, so the JWT/API key/Basic settings and the outbound
stack are omitted. Every value comes from the environment (pydantic-settings) and has no
default, so a missing pepper or credential list stops startup instead of silently disabling
authentication (fail closed).
"""

from collections.abc import Sequence

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from security.inbound.app_credentials_provider import (
    AppCredentialRecord,
    AppCredentialsAuthenticationProvider,
    InMemoryAppCredentialStore,
)
from security.inbound.authentication_manager import AuthenticationManager
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.exception_handlers import install_security_exception_handlers
from security.inbound.middleware import SecurityMiddleware


class AppCredentialEntry(BaseModel):
    """One registered application. Holds the peppered HMAC hash of its secret key, never the secret."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Non-secret identifier, safe to log. Restricted charset (no NUL) keeps the
    # application_id + NUL + secret hash encoding unambiguous.
    application_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    # 64 lowercase hex chars = HMAC-SHA256 digest; rejects a raw secret pasted by mistake.
    secret_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    subject: str = Field(min_length=1)
    authorities: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    tenant_id: str | None = None
    enabled: bool = True

    def to_record(self) -> AppCredentialRecord:
        return AppCredentialRecord(
            application_id=self.application_id,
            secret_hash=self.secret_hash,
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
    """Env: SECURITY_INBOUND_APP_CREDENTIALS_PEPPER,
    SECURITY_INBOUND_APP_CREDENTIALS='[{"application_id": ..., "secret_hash": ...}]'."""

    model_config = SettingsConfigDict(env_prefix="SECURITY_INBOUND_", extra="ignore")

    # No defaults: missing configuration must fail startup.
    app_credentials_pepper: SecretStr
    app_credentials: tuple[AppCredentialEntry, ...] = Field(min_length=1)
    application_id_header: str = "X-Application-Id"
    secret_key_header: str = "X-Secret-Key"  # noqa: S105 - header name, not a secret
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
    """Application credentials are the only accepted mechanism for this service."""
    store = InMemoryAppCredentialStore([entry.to_record() for entry in settings.app_credentials])
    # Provider enforces a >= 32-byte pepper.
    pepper = settings.app_credentials_pepper.get_secret_value().encode()
    return [
        AppCredentialsAuthenticationProvider(
            store,
            pepper,
            application_id_header=settings.application_id_header,
            secret_key_header=settings.secret_key_header,
        )
    ]


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
