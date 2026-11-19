# Configuration & Application Wiring Reference

How to plug the inbound and outbound frameworks into a FastAPI application: settings,
lifespan, middleware order, and dependency injection of service clients.

## 1. Package layout to generate

```text
<app>/
├── main.py
├── security/                       ← copy from templates/security, keep reusable
│   ├── exceptions.py
│   ├── configuration.py
│   ├── inbound/
│   │   ├── principal.py            SecurityPrincipal, SecurityContext
│   │   ├── context_holder.py       ContextVar + SecurityContextHolder + create_detached_task
│   │   ├── authentication_provider.py
│   │   ├── jwt_provider.py
│   │   ├── api_key_provider.py
│   │   ├── basic_auth_provider.py
│   │   ├── authentication_manager.py
│   │   ├── middleware.py
│   │   ├── policies.py
│   │   ├── authorization.py
│   │   ├── decorators.py
│   │   ├── dependencies.py
│   │   └── exception_handlers.py
│   └── outbound/
│       ├── service_registry.py
│       ├── credential_provider.py
│       ├── request_context.py
│       ├── interceptor_manager.py
│       ├── token_provider.py
│       ├── secure_http_client.py
│       ├── service_client.py
│       └── interceptors/{base,api_key,basic_auth,oauth2,correlation_id}.py
├── services/   (business logic: @pre_authorize here)
├── clients/    (typed downstream clients wrapping ServiceClient)
└── api/routes/ (FastAPI routers: Depends(require(...)) here)
```

Only include what the task needs (e.g. omit `basic_auth_provider.py` if Basic is not used), but
keep the module names so the structure stays recognisable across services.

Dependencies (`pyproject.toml`):

```toml
dependencies = [
  "fastapi>=0.110",
  "httpx>=0.27",
  "pyjwt[crypto]>=2.8",
  "pydantic>=2.6",
  "pydantic-settings>=2.2",
  # "argon2-cffi>=23.1",   # if Basic auth with argon2id
]
[dependency-groups]
dev = ["pytest>=8", "pytest-asyncio>=0.23", "ruff", "mypy"]
```

## 2. Settings and factory

12-factor: everything from environment variables via `pydantic-settings`; secrets are
`SecretStr` or resolved through a `SecretStore`; nothing secret in YAML or source.

```python
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
```

Example environment:

```bash
SECURITY_INBOUND_JWT_ISSUER=https://idp.example.com/
SECURITY_INBOUND_JWT_AUDIENCE=orders-api
SECURITY_INBOUND_JWT_JWKS_URL=https://idp.example.com/.well-known/jwks.json
SECURITY_OUTBOUND_SERVICES='{
  "BILLING":   {"service_id": "BILLING",   "base_url": "https://billing.internal",   "auth_type": "API_KEY", "credential_ref": "billing"},
  "INVENTORY": {"service_id": "INVENTORY", "base_url": "https://inventory.internal", "auth_type": "OAUTH2_CLIENT_CREDENTIALS",
                "credential_ref": "inventory", "token_url": "https://idp.example.com/oauth/token", "scopes": ["stock.read"]}
}'
# Secrets (injected by the platform / secrets manager, never committed):
OUTBOUND_BILLING__API_KEY=...
OUTBOUND_INVENTORY__CLIENT_ID=...
OUTBOUND_INVENTORY__CLIENT_SECRET=...
```

Fail closed: if JWT is enabled but issuer/audience/key source are missing, `JwtSettings`
raises at import/startup. Never default to "auth disabled".

## 3. main.py

```python
"""Example application wiring. Run: uvicorn main:app"""
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Request

from security.configuration import (
    InboundSettings,
    OutboundSecurity,
    OutboundSettings,
    configure_inbound_security,
    outbound_security,
)
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.decorators import pre_authorize
from security.inbound.dependencies import CurrentPrincipal, require_authority
from security.inbound.jwt_provider import JwtAuthenticationProvider, JwtSettings
from security.inbound.policies import has_authority
from security.outbound.service_client import ServiceClient


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with outbound_security(OutboundSettings()) as outbound:
        app.state.outbound = outbound
        yield


def build_providers(settings: InboundSettings) -> list[AuthenticationProvider]:
    providers: list[AuthenticationProvider] = []
    if settings.jwt_enabled:
        providers.append(
            JwtAuthenticationProvider(
                JwtSettings(
                    issuer=settings.jwt_issuer,
                    audience=settings.jwt_audience,
                    jwks_url=settings.jwt_jwks_url,
                    algorithms=settings.jwt_algorithms,
                )
            )
        )
    return providers


inbound_settings = InboundSettings()
app = FastAPI(lifespan=lifespan)
configure_inbound_security(app, build_providers(inbound_settings), inbound_settings.public_paths)


def billing_client(request: Request) -> ServiceClient:
    outbound: OutboundSecurity = request.app.state.outbound
    return outbound.client_for("BILLING")


class InvoiceService:
    def __init__(self, billing: ServiceClient) -> None:
        self._billing = billing

    @pre_authorize(has_authority("INVOICE_READ"))
    async def list_invoices(self, customer_id: str) -> list[dict]:
        response = await self._billing.get("/v1/invoices", params={"customer": customer_id})
        return response.json()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/invoices", dependencies=[Depends(require_authority("INVOICE_READ"))])
async def list_invoices(
    principal: CurrentPrincipal,
    billing: Annotated[ServiceClient, Depends(billing_client)],
) -> list[dict]:
    return await InvoiceService(billing).list_invoices(principal.subject)
```

Middleware order (Starlette: last added = outermost):

```python
configure_inbound_security(app, providers, public_paths)   # inner
app.add_middleware(CORSMiddleware, allow_origins=[...])     # outer: preflights bypass auth
# correlation-id / request-logging middleware: add after CORS so it is outermost and
# sets correlation_id_var before security runs.
```

## 4. Injecting service clients

Expose clients through FastAPI dependencies reading `request.app.state` (see `billing_client` in
`main.py`), or build typed clients once in the lifespan and store them on `app.state`. Tests
override with `app.dependency_overrides[billing_client] = lambda: fake`.

## 5. Non-HTTP entry points

Kafka consumers, schedulers, CLI jobs have no inbound request. If they call `@pre_authorize`
services, bind an explicit, least-privilege service principal:

```python
SYSTEM = SecurityPrincipal(subject="svc:order-sync", authentication_type="SYSTEM",
                           authorities={"ORDER_READ"})
with SecurityContextHolder.use(SecurityContext(SYSTEM)):
    await order_service.sync()
```

Outbound calls from these entry points use the same `SecureHttpClient` built in their own
startup (`async with outbound_security(OutboundSettings()) as outbound:`).

## 6. Spring Security mapping (for reviewers coming from Java)

| Spring Security | This framework |
|---|---|
| SecurityFilterChain / OncePerRequestFilter | `SecurityMiddleware` (pure ASGI) |
| AuthenticationManager / AuthenticationProvider | same names |
| Authentication / principal | `SecurityPrincipal` |
| SecurityContext / SecurityContextHolder | same names, `ContextVar`-backed |
| GrantedAuthority / Role | `authorities` / `roles` frozensets |
| `@PreAuthorize`, `@PostAuthorize`, `@Secured` | `@pre_authorize`, `@post_authorize`, `@secured` |
| `permitAll()` | `public_paths` |
| AccessDeniedException / AuthenticationException | `AuthorizationException` / `AuthenticationException` |
| RestTemplate interceptor / WebClient filter | `RequestInterceptor` / `AuthenticationInterceptor` |
| OAuth2AuthorizedClientManager | `ClientCredentialsTokenProvider` |
