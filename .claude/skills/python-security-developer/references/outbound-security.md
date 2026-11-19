# Outbound Security Reference — Authenticated Calls to Other Services

How the application calls downstream services without business code knowing how they
authenticate. All code below is the tested reference implementation
(`templates/security/outbound/`). Copy it, then adapt.

Target: Python ≥ 3.11, HTTPX ≥ 0.27, Pydantic v2.

## 1. Request flow

```text
billing_client.get("/v1/invoices", params=...)          ← ServiceClient bound to "BILLING"
  └─ SecureHttpClient.request("BILLING", "GET", path)
       ├─ ServiceRegistry.get("BILLING")                   unknown → OutboundSecurityException
       ├─ _resolve_url: relative path only, under base_url (no "//", "://", "..", "?", "#", "\")
       ├─ _check_headers: caller may not set Authorization / Cookie / Host / the API-key header
       ├─ build_request (fresh per attempt)
       ├─ InterceptorManager.execute
       │     ├─ general interceptors (ordered): correlation id, tracing...   ← never see credentials
       │     └─ exactly ONE AuthenticationInterceptor chosen by service.auth_type
       ├─ _assert_destination: final URL origin == registered origin, https only
       ├─ http_client.send(follow_redirects=False)
       ├─ 401 → auth.on_unauthorized() (OAuth2: invalidate token) → one retry
       ├─ 502/503/504/transport error → retry with backoff, idempotent methods only
       └─ non-2xx → OutboundServiceError(service_id, status) — no URL query, headers or body
```

Key differences from a naive interceptor design:

| Naive | This framework | Why |
|---|---|---|
| `supports()` compares hard-coded service ids | auth chosen by `ServiceConfig.auth_type` | Config-driven; impossible to attach two auth strategies |
| Interceptors in one list | general interceptors + one auth interceptor, auth runs **last** | Logging/tracing interceptors never see secrets |
| `response.raise_for_status()` | `OutboundServiceError` with status only | httpx's error message embeds the full URL (query may carry secrets) |
| Caller passes a URL | caller passes a relative path; origin re-checked after interceptors | SSRF and credential exfiltration to foreign hosts |
| Redirects followed | `follow_redirects=False` everywhere | Credentials must never be forwarded to a redirect target |

## 2. Service registry

Holds metadata and secret *references* only. Pydantic validation fails at startup on plain
http, embedded userinfo, missing `credential_ref`, or non-https token URLs. `allow_insecure_http` is
accepted only for loopback hosts (`localhost`, `127.0.0.0/8`, `::1`), so a dev config copied to
another environment cannot send credentials over plaintext.

```python
import ipaddress
from collections.abc import Mapping
from enum import StrEnum

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from security.exceptions import OutboundSecurityException


class AuthType(StrEnum):
    NONE = "NONE"
    API_KEY = "API_KEY"
    BASIC = "BASIC"
    OAUTH2_CLIENT_CREDENTIALS = "OAUTH2_CLIENT_CREDENTIALS"


class ServiceConfig(BaseModel):
    """Metadata for one downstream service. Holds secret *references*, never secrets."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service_id: str
    base_url: str
    auth_type: AuthType
    credential_ref: str | None = None
    api_key_header: str = "X-API-Key"
    token_url: str | None = None
    scopes: tuple[str, ...] = ()
    connect_timeout: float = Field(default=3.0, gt=0)
    read_timeout: float = Field(default=10.0, gt=0)
    max_retries: int = Field(default=2, ge=0, le=5)
    allow_insecure_http: bool = False  # local development only; loopback hosts only

    @model_validator(mode="after")
    def _validate(self) -> "ServiceConfig":
        url = httpx.URL(self.base_url)
        if url.scheme not in ("https", "http") or not url.host:
            raise ValueError(f"{self.service_id}: base_url must be an absolute http(s) URL")
        if url.scheme == "http" and not self.allow_insecure_http:
            raise ValueError(f"{self.service_id}: base_url must use https")
        if self.allow_insecure_http and not _is_loopback(url.host):
            raise ValueError(f"{self.service_id}: allow_insecure_http is only permitted for loopback hosts")
        if url.userinfo or url.query or url.fragment:
            raise ValueError(f"{self.service_id}: base_url must not contain credentials, query or fragment")
        if self.auth_type is not AuthType.NONE and not self.credential_ref:
            raise ValueError(f"{self.service_id}: credential_ref is required for {self.auth_type}")
        if self.auth_type is AuthType.OAUTH2_CLIENT_CREDENTIALS:
            if not self.token_url or httpx.URL(self.token_url).scheme != "https":
                raise ValueError(f"{self.service_id}: token_url must be an https URL")
        return self

    @property
    def origin(self) -> tuple[str, str, int | None]:
        url = httpx.URL(self.base_url)
        return url.scheme, url.host, url.port

    @property
    def timeout(self) -> httpx.Timeout:
        return httpx.Timeout(self.read_timeout, connect=self.connect_timeout)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ServiceRegistry:
    def __init__(self, services: Mapping[str, ServiceConfig]) -> None:
        for key, config in services.items():
            if key != config.service_id:
                raise ValueError(f"Registry key {key!r} does not match service_id {config.service_id!r}")
        self._services = dict(services)

    def get(self, service_id: str) -> ServiceConfig:
        try:
            return self._services[service_id]
        except KeyError:
            raise OutboundSecurityException(f"Unknown service: {service_id!r}") from None

    def all(self) -> list[ServiceConfig]:
        return list(self._services.values())
```

## 3. Secrets

```python
import os
import re
from typing import Protocol


class SecretStore(Protocol):
    """Resolves secret references (AWS Secrets Manager, Vault, K8s secrets, env...)."""

    async def get_secret(self, reference: str, key: str) -> str: ...


class EnvSecretStore:
    """Reads `<PREFIX><REFERENCE>__<KEY>` env vars, e.g. ref `service-b-basic-auth`, key
    `password` -> `OUTBOUND_SERVICE_B_BASIC_AUTH__PASSWORD`. Suitable when the platform
    injects secrets as env vars; otherwise implement SecretStore over your secrets manager."""

    def __init__(self, prefix: str = "OUTBOUND_") -> None:
        self._prefix = prefix

    async def get_secret(self, reference: str, key: str) -> str:
        name = f"{self._prefix}{_env_part(reference)}__{_env_part(key)}"
        value = os.environ.get(name)
        if not value:
            # Name the variable, never the value.
            raise LookupError(f"Secret not configured: {name}")
        return value


def _env_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", value).upper()
```

Secret keys used by the interceptors, per `credential_ref`:

| auth_type | keys |
|---|---|
| `API_KEY` | `api_key` |
| `BASIC` | `username`, `password` |
| `OAUTH2_CLIENT_CREDENTIALS` | `client_id`, `client_secret` |

For AWS Secrets Manager / Vault, implement `SecretStore.get_secret` (async; use
`aioboto3`/`hvac` in a thread) with a short in-memory TTL cache so rotation is picked up.

## 4. Request context

```python
from dataclasses import dataclass, field
from typing import Any

import httpx

from security.outbound.service_registry import ServiceConfig


@dataclass
class RequestContext:
    service: ServiceConfig
    request: httpx.Request
    attempt: int = 1
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def service_id(self) -> str:
        return self.service.service_id
```

## 5. Interceptors

### 5.1 Contracts

```python
from abc import ABC, abstractmethod
from typing import ClassVar

import httpx

from security.outbound.request_context import RequestContext
from security.outbound.service_registry import AuthType


class RequestInterceptor(ABC):
    """Non-authentication concern (correlation id, tracing, headers). Many may apply.

    Interceptors run BEFORE authentication, so they never see credentials."""

    order: ClassVar[int] = 0

    def supports(self, context: RequestContext) -> bool:
        return True

    @abstractmethod
    async def intercept(self, context: RequestContext) -> None: ...


class AuthenticationInterceptor(ABC):
    """Exactly one per AuthType; selected by the service's configured auth_type,
    never by hard-coded service ids."""

    auth_type: ClassVar[AuthType]

    @abstractmethod
    async def intercept(self, context: RequestContext) -> None: ...

    async def on_unauthorized(self, context: RequestContext, response: httpx.Response) -> bool:
        """Called on a 401. Return True if credentials were refreshed and one retry is worthwhile."""
        return False


class NoAuthInterceptor(AuthenticationInterceptor):
    auth_type = AuthType.NONE

    async def intercept(self, context: RequestContext) -> None:
        return None
```

### 5.2 API key

```python
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
```

### 5.3 Basic

```python
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
```

### 5.4 OAuth2 client credentials

The interceptor only attaches a token; the `TokenProvider` owns acquisition, caching (per
service), early refresh (`refresh_skew_seconds`), and a per-service `asyncio.Lock` with
double-checked caching so N concurrent callers trigger one token request. On a downstream
401 the token is invalidated (only if it is still the cached one) and the call is retried once.

```python
import asyncio
import logging
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from security.exceptions import OutboundServiceError
from security.outbound.credential_provider import SecretStore
from security.outbound.service_registry import ServiceConfig

logger = logging.getLogger(__name__)


class TokenProvider(ABC):
    @abstractmethod
    async def get_access_token(self, service: ServiceConfig) -> str: ...

    @abstractmethod
    def invalidate(self, service: ServiceConfig, token: str) -> None: ...


@dataclass(frozen=True)
class _CachedToken:
    value: str
    expires_at: float


class ClientCredentialsTokenProvider(TokenProvider):
    """OAuth2 client-credentials tokens, cached per service, refreshed before expiry,
    with a per-service lock so concurrent callers trigger a single token request."""

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        secrets: SecretStore,
        *,
        refresh_skew_seconds: float = 60.0,
        default_expires_in: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        # Use the raw client: token calls must not go through the interceptor pipeline.
        self._http = http_client
        self._secrets = secrets
        self._skew = refresh_skew_seconds
        self._default_expires_in = default_expires_in
        self._clock = clock
        self._cache: dict[str, _CachedToken] = {}
        self._locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def get_access_token(self, service: ServiceConfig) -> str:
        key = service.service_id
        cached = self._cache.get(key)
        if cached and self._clock() < cached.expires_at:
            return cached.value
        async with self._locks[key]:
            cached = self._cache.get(key)  # another caller may have refreshed while we waited
            if cached and self._clock() < cached.expires_at:
                return cached.value
            token = await self._fetch(service)
            self._cache[key] = token
            return token.value

    def invalidate(self, service: ServiceConfig, token: str) -> None:
        """Drop the token only if it is still the cached one (avoids discarding a fresh token)."""
        cached = self._cache.get(service.service_id)
        if cached and cached.value == token:
            del self._cache[service.service_id]

    async def _fetch(self, service: ServiceConfig) -> _CachedToken:
        assert service.token_url and service.credential_ref
        client_id = await self._secrets.get_secret(service.credential_ref, "client_id")
        client_secret = await self._secrets.get_secret(service.credential_ref, "client_secret")
        data = {"grant_type": "client_credentials"}
        if service.scopes:
            data["scope"] = " ".join(service.scopes)
        try:
            response = await self._http.post(
                service.token_url,
                data=data,
                auth=httpx.BasicAuth(client_id, client_secret),  # client_secret_basic
                timeout=service.timeout,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise OutboundServiceError(service.service_id, None, f"token endpoint unreachable ({type(exc).__name__})") from None
        if response.status_code != 200:
            # Never log the response body: it may echo credentials.
            raise OutboundServiceError(service.service_id, response.status_code, "token request failed")
        try:
            payload = response.json()
            access_token = payload["access_token"]
            token_type = payload.get("token_type", "Bearer")
            expires_in = float(payload.get("expires_in", self._default_expires_in))
        except (ValueError, KeyError, TypeError):
            raise OutboundServiceError(service.service_id, 200, "malformed token response") from None
        if not isinstance(access_token, str) or not access_token or token_type.lower() != "bearer":
            raise OutboundServiceError(service.service_id, 200, "unsupported token response")
        logger.info("OAuth2 token refreshed", extra={"service_id": service.service_id, "expires_in": expires_in})
        return _CachedToken(access_token, self._clock() + max(expires_in - self._skew, 0.0))
```

```python
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
```

Variants:
- `client_secret_post`: send `client_id`/`client_secret` in the form body instead of `auth=`.
- `private_key_jwt`: sign a client assertion with PyJWT and send
  `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
- Token exchange / on-behalf-of (forward user identity): a separate interceptor that reads
  `SecurityContextHolder.get_principal()` and exchanges the *inbound* token (RFC 8693). Never
  forward the raw inbound user token to third parties.
- Multi-instance deployments that must share tokens: back the cache with Redis, keep the
  in-process lock, and encrypt tokens at rest.

### 5.5 Correlation id (general interceptor example)

```python
import contextvars

from security.outbound.interceptors.base import RequestInterceptor
from security.outbound.request_context import RequestContext

correlation_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("correlation_id", default=None)


class CorrelationIdInterceptor(RequestInterceptor):
    order = -100

    def __init__(self, header_name: str = "X-Correlation-ID") -> None:
        self._header = header_name

    async def intercept(self, context: RequestContext) -> None:
        correlation_id = correlation_id_var.get()
        if correlation_id:
            context.request.headers[self._header] = correlation_id
```

## 6. Interceptor manager

```python
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
```

`validate(registry)` runs in the `SecureHttpClient` constructor: a service whose `auth_type`
has no interceptor fails application startup, not the first request.

## 7. Secure HTTP client

```python
import asyncio
import logging
import random
import time
from collections.abc import Mapping
from typing import Any

import httpx

from security.exceptions import OutboundSecurityException, OutboundServiceError
from security.outbound.interceptor_manager import InterceptorManager
from security.outbound.request_context import RequestContext
from security.outbound.service_registry import ServiceConfig, ServiceRegistry

logger = logging.getLogger(__name__)

_IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
_RETRYABLE_STATUS = frozenset({502, 503, 504})
_RESERVED_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "host"})


class SecureHttpClient:
    """The only way application code talks to registered downstream services."""

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        registry: ServiceRegistry,
        interceptors: InterceptorManager,
        *,
        backoff_base_seconds: float = 0.2,
    ) -> None:
        self._http = http_client
        self._registry = registry
        self._interceptors = interceptors
        self._backoff = backoff_base_seconds
        interceptors.validate(registry)

    async def request(
        self,
        service_id: str,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        json: Any = None,
        content: bytes | None = None,
        data: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        service = self._registry.get(service_id)
        method = method.upper()
        url = self._resolve_url(service, path)
        safe_headers = self._check_headers(service, headers)
        retries = service.max_retries if self._retryable(method, safe_headers) else 0

        attempt = 0
        unauthorized_retry_used = False
        while True:
            attempt += 1
            request = self._http.build_request(
                method, url, params=params, headers=safe_headers, json=json, content=content, data=data,
                timeout=service.timeout,
            )
            context = RequestContext(service=service, request=request, attempt=attempt)
            auth = await self._interceptors.execute(context)
            self._assert_destination(service, context.request.url)

            started = time.perf_counter()
            try:
                response = await self._http.send(context.request, follow_redirects=False)
            except httpx.TransportError as exc:
                if attempt <= retries:
                    await self._sleep(attempt)
                    continue
                logger.warning("Outbound request failed", extra=self._log_fields(service, method, path, None, started))
                raise OutboundServiceError(service_id, None, f"transport error ({type(exc).__name__})") from None

            logger.info("Outbound request completed", extra=self._log_fields(service, method, path, response.status_code, started))

            if response.status_code == 401 and not unauthorized_retry_used:
                unauthorized_retry_used = True
                if await auth.on_unauthorized(context, response):
                    await response.aclose()
                    continue
            if response.status_code in _RETRYABLE_STATUS and attempt <= retries:
                await response.aclose()
                await self._sleep(attempt)
                continue
            if not response.is_success:
                # Never put the URL (query may hold secrets) or body in the message.
                raise OutboundServiceError(service_id, response.status_code, f"{method} {path} returned {response.status_code}")
            return response

    @staticmethod
    def _resolve_url(service: ServiceConfig, path: str) -> httpx.URL:
        """Only relative paths under the registered base URL are allowed (SSRF / credential-leak guard)."""
        if (
            not path.startswith("/")
            or path.startswith("//")
            or "://" in path
            or "\\" in path
            or "?" in path
            or "#" in path
            or any(segment in ("..", ".") for segment in path.split("/"))
        ):
            raise OutboundSecurityException("Path must be a relative path under the service base URL; use params= for queries")
        base = httpx.URL(service.base_url)
        return base.copy_with(path=base.path.rstrip("/") + path)

    @staticmethod
    def _assert_destination(service: ServiceConfig, url: httpx.URL) -> None:
        if (url.scheme, url.host, url.port) != service.origin:
            raise OutboundSecurityException(f"Destination does not match registered origin for {service.service_id}")
        if url.scheme != "https" and not service.allow_insecure_http:
            raise OutboundSecurityException("Credentials may only be sent over https")

    @staticmethod
    def _check_headers(service: ServiceConfig, headers: Mapping[str, str] | None) -> dict[str, str]:
        if not headers:
            return {}
        reserved = _RESERVED_HEADERS | {service.api_key_header.lower()}
        clash = [name for name in headers if name.lower() in reserved]
        if clash:
            raise OutboundSecurityException(f"Caller may not set credential headers: {clash}")
        return dict(headers)

    @staticmethod
    def _retryable(method: str, headers: Mapping[str, str]) -> bool:
        # Non-idempotent calls retry only when the caller supplies an idempotency key.
        return method in _IDEMPOTENT or any(name.lower() == "idempotency-key" for name in headers)

    async def _sleep(self, attempt: int) -> None:
        await asyncio.sleep(self._backoff * (2 ** (attempt - 1)) * (0.5 + random.random()))  # noqa: S311 - jitter, not crypto

    @staticmethod
    def _log_fields(service: ServiceConfig, method: str, path: str, status: int | None, started: float) -> dict[str, Any]:
        return {
            "service_id": service.service_id,
            "auth_type": str(service.auth_type),
            "method": method,
            "path": path,  # path only; query strings and headers are never logged
            "status": status,
            "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        }
```

Retry policy: GET/HEAD/OPTIONS/PUT/DELETE retry on transport errors and 502/503/504 with
exponential backoff + jitter, up to `max_retries`. POST/PATCH retry only when the caller sends an
`Idempotency-Key` header. 4xx is never retried (except the single 401 credential refresh).

Streaming large downloads: add a `stream()` async context manager that uses
`self._http.send(request, stream=True)` with the same URL/header/destination checks; do not
retry streams.

## 8. Service-bound clients

```python
from typing import Any

import httpx

from security.outbound.secure_http_client import SecureHttpClient


class ServiceClient:
    """Client bound to one registered service, so callers cannot pick the wrong credentials."""

    def __init__(self, secure_client: SecureHttpClient, service_id: str) -> None:
        self._client = secure_client
        self.service_id = service_id

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return await self._client.request(self.service_id, method, path, **kwargs)

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", path, **kwargs)

    async def put(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", path, **kwargs)

    async def patch(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PATCH", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", path, **kwargs)
```

Wrap these in typed, domain-level clients so business code never handles raw responses:

```python
class BillingClient:
    def __init__(self, client: ServiceClient) -> None:
        self._client = client

    async def list_invoices(self, customer_id: str) -> list[Invoice]:
        response = await self._client.get("/v1/invoices", params={"customer": customer_id})
        return [Invoice.model_validate(i) for i in response.json()]
```

Validate downstream responses with Pydantic: a compromised or buggy dependency is untrusted input.

## 9. HTTPX client lifecycle

One shared `httpx.AsyncClient` per process, created in the FastAPI lifespan, closed on shutdown.
Never create a client per request. See `configuration-and-wiring.md`. Required settings:

| Setting | Why |
|---|---|
| `follow_redirects=False` | credentials must never follow a redirect |
| explicit `timeout` and `limits` | no unbounded hangs or pool exhaustion |
| `trust_env=False` | the default honours `HTTP(S)_PROXY`/`ALL_PROXY` and `.netrc`, which could route credentials through a proxy (in plaintext over http) or inject credentials. If a corporate proxy is required, configure it explicitly with `proxy=` |
| cookie jar with a reject-all policy (`http_client.cookies.jar.set_policy(...)`) | the shared jar would otherwise store a downstream's `Set-Cookie` and replay it to other services (cookie matching ignores ports, so all `127.0.0.1` services share cookies) and on behalf of other users. **Do not** pass `cookies=httpx.Cookies(CookieJar(policy=...))`: httpx copies the cookies into a new jar and the policy is lost |

mTLS to a downstream: pass `verify=ssl_context` and a client certificate via an
`ssl.SSLContext` (`ctx.load_cert_chain(...)`) when constructing the shared client — or a separate
client per mTLS service. Never set `verify=False`.

## 10. Logging rules (outbound)

Log: service id, auth type, method, path (no query), status, duration, token refresh events
(service, `expires_in`). Never log: headers, query strings, request/response bodies of auth
calls, tokens, API keys, passwords, client secrets.
