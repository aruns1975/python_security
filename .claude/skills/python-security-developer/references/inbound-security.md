# Inbound Security Reference — Authentication & Authorization

How this framework authenticates incoming FastAPI/ASGI requests, binds the identity to the
request, and enforces authorization. All code below is the tested reference implementation
(`templates/security/inbound/`). Copy it, then adapt; do not re-invent it.

Target: Python ≥ 3.11, FastAPI ≥ 0.110, Starlette, PyJWT[crypto] ≥ 2.8.

## 1. Request flow

```text
HTTP request
  └─ SecurityMiddleware (pure ASGI, outermost security layer)
       ├─ AuthenticationManager.authenticate(HTTPConnection)
       │     ├─ zero providers support()  → anonymous (None)
       │     ├─ >1 providers support()    → 401 "Ambiguous authentication"
       │     └─ exactly one               → provider.authenticate() → SecurityPrincipal | 401
       ├─ anonymous + non-public path     → 401 + WWW-Authenticate
       ├─ token = SecurityContextHolder.set_context(SecurityContext(principal))
       ├─ try: await app(...)             → endpoint deps (require(...)) / service decorators (@pre_authorize)
       └─ finally: SecurityContextHolder.reset_context(token)
```

Rules that drive this design:

| Rule | Why |
|---|---|
| Pure ASGI middleware, not `BaseHTTPMiddleware` | Correct ContextVar propagation, streaming, no per-request task overhead. |
| Middleware writes its own 401 response | `app.exception_handler` handlers run *inside* user middleware; an exception raised in middleware becomes a 500. |
| Invalid credentials are rejected even on public paths | A forged/expired token must never silently degrade to anonymous. |
| Multiple credential types on one request → 401 | Deterministic, no precedence surprises. |
| `reset_context(token)` in `finally` | Identity never leaks into the next request or after an exception. |
| Providers never read the body | Authentication happens before routing; reading `receive` would consume the body. |

## 2. Exceptions

All exceptions live in `security/exceptions.py` and are shared with outbound. Messages are
client-visible — keep them generic.

```python
"""Security exception hierarchy.

Messages on these exceptions are returned to clients, so they must never
contain credentials, token contents or internal details.
"""


class SecurityException(Exception):
    """Base class for all framework security errors."""


class AuthenticationException(SecurityException):
    """Authentication failed or is required (HTTP 401)."""

    def __init__(self, message: str = "Authentication required", *, scheme: str = "Bearer") -> None:
        super().__init__(message)
        self.scheme = scheme


class AuthorizationException(SecurityException):
    """The authenticated identity lacks permission (HTTP 403)."""

    def __init__(self, message: str = "Access denied") -> None:
        super().__init__(message)


class OutboundSecurityException(SecurityException):
    """An outbound call violated security configuration (unknown service,
    foreign destination, caller-supplied credentials, plain HTTP...)."""


class OutboundServiceError(Exception):
    """A registered downstream service returned a non-success response or
    could not be reached. Carries no headers or credentials."""

    def __init__(self, service_id: str, status_code: int | None, message: str) -> None:
        super().__init__(f"{service_id}: {message}")
        self.service_id = service_id
        self.status_code = status_code
```

## 3. Principal and context

Immutable value objects. `claims` is copied into a read-only `MappingProxyType`; authorities and
roles are coerced to `frozenset`. `claims` is excluded from `repr` (it may contain PII) and from
hashing/equality.

```python
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any


@dataclass(frozen=True, slots=True)
class SecurityPrincipal:
    """Immutable authenticated identity (user or service)."""

    subject: str
    authentication_type: str
    username: str | None = None
    tenant_id: str | None = None
    authorities: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    claims: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def __post_init__(self) -> None:
        # Normalise so callers may pass any iterable / dict without breaking immutability.
        object.__setattr__(self, "authorities", frozenset(self.authorities))
        object.__setattr__(self, "roles", frozenset(self.roles))
        object.__setattr__(self, "claims", MappingProxyType(dict(self.claims)))

    def has_authority(self, authority: str) -> bool:
        return authority in self.authorities

    def has_role(self, role: str) -> bool:
        return role in self.roles


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Security information bound to the current request."""

    principal: SecurityPrincipal | None = None

    @property
    def authenticated(self) -> bool:
        return self.principal is not None

    @property
    def authentication_type(self) -> str | None:
        return self.principal.authentication_type if self.principal else None


ANONYMOUS_CONTEXT = SecurityContext()
```

## 4. SecurityContextHolder (ContextVar)

`ContextVar`, never a module global or `threading.local()` — concurrent requests interleave on
one thread.

```python
import asyncio
import contextvars
from collections.abc import Coroutine, Iterator
from contextlib import contextmanager
from typing import Any, TypeVar

from security.exceptions import AuthenticationException
from security.inbound.principal import SecurityContext, SecurityPrincipal

T = TypeVar("T")

# ContextVar, never a global or threading.local(): concurrent requests share threads.
_security_context: contextvars.ContextVar[SecurityContext | None] = contextvars.ContextVar(
    "security_context", default=None
)


class SecurityContextHolder:
    """Spring-style facade over the request-scoped security context."""

    @staticmethod
    def get_context() -> SecurityContext | None:
        return _security_context.get()

    @staticmethod
    def get_principal() -> SecurityPrincipal | None:
        context = _security_context.get()
        return context.principal if context else None

    @staticmethod
    def require_principal() -> SecurityPrincipal:
        principal = SecurityContextHolder.get_principal()
        if principal is None:
            raise AuthenticationException()
        return principal

    @staticmethod
    def set_context(context: SecurityContext | None) -> contextvars.Token[SecurityContext | None]:
        return _security_context.set(context)

    @staticmethod
    def reset_context(token: contextvars.Token[SecurityContext | None]) -> None:
        _security_context.reset(token)

    @staticmethod
    @contextmanager
    def use(context: SecurityContext | None) -> Iterator[None]:
        """Temporarily bind a context (tests, system jobs). Always restored."""
        token = _security_context.set(context)
        try:
            yield
        finally:
            _security_context.reset(token)


def create_detached_task(coro: Coroutine[Any, Any, T], *, name: str | None = None) -> asyncio.Task[T]:
    """Start a task that keeps other context (correlation id, tracing) but does
    NOT inherit the caller's security identity. Use for fire-and-forget work
    that outlives the request."""
    ctx = contextvars.copy_context()
    ctx.run(_security_context.set, None)
    return asyncio.create_task(coro, name=name, context=ctx)
```

Propagation facts the implementation relies on:

| Situation | Identity visible? | Note |
|---|---|---|
| Plain `await` | yes | same context |
| `asyncio.create_task` / `gather` | yes (copy) | child changes do not leak back |
| `asyncio.to_thread`, Starlette `run_in_threadpool` | yes | context copied |
| `loop.run_in_executor` / raw `ThreadPoolExecutor` | **no** | wrap with `contextvars.copy_context().run` |
| Starlette `BackgroundTasks` | **yes** — they run before the middleware's `finally` | if the job must not act as the user, start it via `create_detached_task` or pass the needed ids explicitly |
| Fire-and-forget task that outlives the request | inherits unless detached | use `create_detached_task` |
| Celery / Kafka consumers / schedulers | no request context | bind an explicit service principal with `SecurityContextHolder.use(...)` |

## 5. Authentication providers

### 5.1 Contract

```python
from abc import ABC, abstractmethod
from typing import ClassVar

from starlette.requests import HTTPConnection

from security.inbound.principal import SecurityPrincipal


class AuthenticationProvider(ABC):
    """One authentication mechanism. Providers must not read the request body."""

    name: ClassVar[str]

    @abstractmethod
    def supports(self, connection: HTTPConnection) -> bool:
        """Cheap check: are this provider's credentials present? No validation here."""

    @abstractmethod
    async def authenticate(self, connection: HTTPConnection) -> SecurityPrincipal:
        """Validate credentials and return a principal, or raise AuthenticationException."""


def parse_authorization(connection: HTTPConnection, scheme: str) -> str | None:
    """Return the credentials part of `Authorization: <scheme> <credentials>`."""
    header = connection.headers.get("authorization")
    if not header:
        return None
    found_scheme, _, credentials = header.partition(" ")
    if found_scheme.lower() != scheme.lower():
        return None
    return credentials.strip()
```

`supports()` is a cheap "are my credentials present?" check. Validation happens only in
`authenticate()`.

### 5.2 JWT Bearer provider

Mandatory checks, all enforced by `jwt.decode`: signature, `exp`, `iat`, `iss`, `aud`, explicit
algorithm allow-list, required claims. Settings guardrails reject `none`, reject mixing HMAC and
asymmetric algorithms (key-confusion attack), require exactly one key source, and require an
https JWKS URL. `PyJWKClient` does blocking I/O, so it runs in `asyncio.to_thread`; it caches the
JWKS and re-fetches on unknown `kid` (key rotation).

```python
import asyncio
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import jwt
from starlette.requests import HTTPConnection

from security.exceptions import AuthenticationException
from security.inbound.authentication_provider import AuthenticationProvider, parse_authorization
from security.inbound.principal import SecurityPrincipal

logger = logging.getLogger(__name__)

_ASYMMETRIC = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
_SYMMETRIC = {"HS256", "HS384", "HS512"}


@dataclass(frozen=True)
class JwtSettings:
    issuer: str
    audience: str
    algorithms: tuple[str, ...] = ("RS256",)
    jwks_url: str | None = None
    static_key: Any = None  # PEM public key, or HMAC secret for HS* (internal use only)
    leeway_seconds: int = 30
    required_claims: tuple[str, ...] = ("exp", "iat", "sub", "iss", "aud")
    authorities_claim: str = "scope"
    roles_claim: str = "roles"
    tenant_claim: str | None = None
    jwks_cache_seconds: int = 300

    def __post_init__(self) -> None:
        algorithms = set(self.algorithms)
        if not algorithms or "none" in {a.lower() for a in algorithms}:
            raise ValueError("JWT algorithms must be explicit and must not include 'none'")
        if algorithms & _SYMMETRIC and algorithms & _ASYMMETRIC:
            # Mixing families enables algorithm-confusion attacks (public key used as HMAC secret).
            raise ValueError("Do not mix symmetric and asymmetric JWT algorithms")
        if (self.jwks_url is None) == (self.static_key is None):
            raise ValueError("Configure exactly one of jwks_url or static_key")
        if self.jwks_url and not self.jwks_url.startswith("https://"):
            raise ValueError("jwks_url must use https")


class JwtAuthenticationProvider(AuthenticationProvider):
    name = "JWT"

    def __init__(self, settings: JwtSettings) -> None:
        self._settings = settings
        self._jwks = (
            jwt.PyJWKClient(settings.jwks_url, cache_jwk_set=True, lifespan=settings.jwks_cache_seconds)
            if settings.jwks_url
            else None
        )

    def supports(self, connection: HTTPConnection) -> bool:
        return parse_authorization(connection, "Bearer") is not None

    async def authenticate(self, connection: HTTPConnection) -> SecurityPrincipal:
        token = parse_authorization(connection, "Bearer")
        if not token:
            raise AuthenticationException("Invalid or expired token")
        s = self._settings
        try:
            key = await self._signing_key(token)
            claims = jwt.decode(
                token,
                key,
                algorithms=list(s.algorithms),
                audience=s.audience,
                issuer=s.issuer,
                leeway=s.leeway_seconds,
                options={"require": list(s.required_claims)},
            )
        except (jwt.PyJWTError, ValueError) as exc:
            # Log the failure class only; never the token.
            logger.info("JWT authentication failed: %s", type(exc).__name__)
            raise AuthenticationException("Invalid or expired token") from None
        return self._to_principal(claims)

    async def _signing_key(self, token: str) -> Any:
        if self._jwks is None:
            return self._settings.static_key
        # PyJWKClient does blocking I/O; keep it off the event loop.
        signing_key = await asyncio.to_thread(self._jwks.get_signing_key_from_jwt, token)
        return signing_key.key

    def _to_principal(self, claims: dict[str, Any]) -> SecurityPrincipal:
        s = self._settings
        return SecurityPrincipal(
            subject=str(claims["sub"]),
            username=claims.get("preferred_username") or claims.get("username"),
            tenant_id=claims.get(s.tenant_claim) if s.tenant_claim else None,
            authorities=_as_strings(claims.get(s.authorities_claim)),
            roles=_as_strings(claims.get(s.roles_claim)),
            claims=claims,
            authentication_type=self.name,
        )


def _as_strings(value: Any) -> frozenset[str]:
    """Accept OAuth2 space-delimited `scope` strings or JSON arrays."""
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset(value.split())
    if isinstance(value, Iterable):
        return frozenset(str(v) for v in value)
    return frozenset()
```

Adapting:
- Keycloak puts roles in `realm_access.roles`; Auth0 uses `permissions`; Entra ID uses `roles`
  and `scp`. Override `_to_principal` or set `authorities_claim` / `roles_claim`.
- Opaque OAuth2 access tokens: write an `IntrospectionAuthenticationProvider` (RFC 7662) using
  the shared `httpx.AsyncClient`, cache results briefly by token hash, and fail closed.
- Token revocation lists, `nbf`, `azp`/`client_id` checks: add to `required_claims` or validate
  in `_to_principal`.

### 5.3 API key provider

API keys are high-entropy random values, so an HMAC-SHA256 with a server-side pepper is the right
storage hash (fast lookup, useless if the DB leaks). Never store raw keys. Compare with
`hmac.compare_digest`. Expose a non-secret `key_id` for logs/audit.

```python
import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from typing import Protocol

from starlette.requests import HTTPConnection

from security.exceptions import AuthenticationException
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.principal import SecurityPrincipal

logger = logging.getLogger(__name__)


def hash_api_key(api_key: str, pepper: bytes) -> str:
    """Keyed hash for storage. API keys are high-entropy random values, so a fast
    HMAC is appropriate (unlike passwords). The pepper lives in a secrets manager."""
    return hmac.new(pepper, api_key.encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class ApiKeyRecord:
    key_id: str  # non-secret identifier, safe to log
    key_hash: str
    subject: str
    authorities: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)
    tenant_id: str | None = None
    enabled: bool = True


class ApiKeyStore(Protocol):
    async def find_by_hash(self, key_hash: str) -> ApiKeyRecord | None: ...


class InMemoryApiKeyStore:
    def __init__(self, records: list[ApiKeyRecord]) -> None:
        self._by_hash = {r.key_hash: r for r in records}

    async def find_by_hash(self, key_hash: str) -> ApiKeyRecord | None:
        return self._by_hash.get(key_hash)


class ApiKeyAuthenticationProvider(AuthenticationProvider):
    name = "API_KEY"

    def __init__(self, store: ApiKeyStore, pepper: bytes, header_name: str = "X-API-Key") -> None:
        if len(pepper) < 32:
            raise ValueError("API key pepper must be at least 32 bytes")
        self._store = store
        self._pepper = pepper
        self._header = header_name

    def supports(self, connection: HTTPConnection) -> bool:
        return self._header in connection.headers

    async def authenticate(self, connection: HTTPConnection) -> SecurityPrincipal:
        presented = connection.headers.get(self._header, "").strip()
        if not presented:
            raise AuthenticationException("Invalid API key", scheme="ApiKey")
        presented_hash = hash_api_key(presented, self._pepper)
        record = await self._store.find_by_hash(presented_hash)
        if record is None or not hmac.compare_digest(record.key_hash, presented_hash) or not record.enabled:
            logger.info("API key authentication failed")
            raise AuthenticationException("Invalid API key", scheme="ApiKey")
        return SecurityPrincipal(
            subject=record.subject,
            tenant_id=record.tenant_id,
            authorities=record.authorities,
            roles=record.roles,
            claims={"key_id": record.key_id},
            authentication_type=self.name,
        )
```

Generate keys with `secrets.token_urlsafe(32)` and show them to the user exactly once. Replace
`InMemoryApiKeyStore` with a DB/Redis-backed store implementing `ApiKeyStore`.

### 5.4 HTTP Basic provider

Passwords need a slow hash (argon2id preferred via `argon2-cffi`; scrypt shown for zero deps).
Verification runs in a thread. Unknown users are verified against a dummy hash so timing does
not reveal valid usernames. Strict base64 decoding.

```python
import asyncio
import base64
import binascii
import hashlib
import hmac
import logging
import os
from dataclasses import dataclass, field
from typing import Protocol

from starlette.requests import HTTPConnection

from security.exceptions import AuthenticationException
from security.inbound.authentication_provider import AuthenticationProvider, parse_authorization
from security.inbound.principal import SecurityPrincipal

logger = logging.getLogger(__name__)


class PasswordHasher(Protocol):
    def hash(self, password: str) -> str: ...
    def verify(self, password_hash: str, password: str) -> bool: ...


class ScryptPasswordHasher:
    """Stdlib-only slow hash. Prefer argon2-cffi's PasswordHasher where the
    dependency is acceptable; both satisfy the PasswordHasher protocol."""

    def __init__(self, n: int = 2**14, r: int = 8, p: int = 1) -> None:
        self._n, self._r, self._p = n, r, p

    def hash(self, password: str) -> str:
        salt = os.urandom(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=self._n, r=self._r, p=self._p)
        return f"scrypt${self._n}${self._r}${self._p}${salt.hex()}${digest.hex()}"

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            _, n, r, p, salt, expected = password_hash.split("$")
            digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p))
        except ValueError:
            return False
        return hmac.compare_digest(digest.hex(), expected)


@dataclass(frozen=True)
class UserRecord:
    username: str
    password_hash: str
    subject: str
    authorities: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)
    tenant_id: str | None = None
    enabled: bool = True


class UserStore(Protocol):
    async def find_by_username(self, username: str) -> UserRecord | None: ...


class BasicAuthenticationProvider(AuthenticationProvider):
    name = "BASIC"

    def __init__(self, store: UserStore, hasher: PasswordHasher, realm: str = "api") -> None:
        self._store = store
        self._hasher = hasher
        self._realm = realm
        # Verified when the user does not exist so response timing does not reveal valid usernames.
        self._dummy_hash = hasher.hash(os.urandom(16).hex())

    def supports(self, connection: HTTPConnection) -> bool:
        return parse_authorization(connection, "Basic") is not None

    async def authenticate(self, connection: HTTPConnection) -> SecurityPrincipal:
        username, password = self._decode(parse_authorization(connection, "Basic") or "")
        user = await self._store.find_by_username(username)
        password_hash = user.password_hash if user else self._dummy_hash
        # Slow hash is CPU-bound; run it off the event loop.
        valid = await asyncio.to_thread(self._hasher.verify, password_hash, password)
        if user is None or not valid or not user.enabled:
            logger.info("Basic authentication failed")
            raise self._failure()
        return SecurityPrincipal(
            subject=user.subject,
            username=user.username,
            tenant_id=user.tenant_id,
            authorities=user.authorities,
            roles=user.roles,
            authentication_type=self.name,
        )

    def _decode(self, credentials: str) -> tuple[str, str]:
        try:
            decoded = base64.b64decode(credentials, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            raise self._failure() from None
        username, sep, password = decoded.partition(":")
        if not sep or not username:
            raise self._failure()
        return username, password

    def _failure(self) -> AuthenticationException:
        return AuthenticationException("Invalid credentials", scheme=f'Basic realm="{self._realm}"')
```

Add rate limiting / lockout (e.g. per username + IP in Redis) in front of Basic and API key
authentication for brute-force protection.

### 5.5 AuthenticationManager

```python
import logging
from collections.abc import Sequence

from starlette.requests import HTTPConnection

from security.exceptions import AuthenticationException
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.principal import SecurityPrincipal

logger = logging.getLogger(__name__)


class AuthenticationManager:
    """Selects exactly one provider for a request and delegates to it."""

    def __init__(self, providers: Sequence[AuthenticationProvider]) -> None:
        names = [p.name for p in providers]
        if len(names) != len(set(names)):
            raise ValueError(f"Duplicate authentication providers: {names}")
        self._providers = tuple(providers)

    async def authenticate(self, connection: HTTPConnection) -> SecurityPrincipal | None:
        """Return a principal, None when no credentials were presented (anonymous),
        or raise AuthenticationException for invalid or ambiguous credentials."""
        matching = [p for p in self._providers if p.supports(connection)]
        if not matching:
            return None
        if len(matching) > 1:
            # Deterministic policy: multiple credential types on one request are rejected.
            raise AuthenticationException("Ambiguous authentication: multiple credentials supplied")
        provider = matching[0]
        principal = await provider.authenticate(connection)
        logger.info("Authentication successful", extra={"auth_type": provider.name, "subject": principal.subject})
        return principal
```

### 5.6 Adding a new provider

1. Subclass `AuthenticationProvider`, set a unique `name`.
2. `supports()` checks only for presence of *its* credential (header/cookie/mTLS cert in
   `scope["extensions"]["tls"]`).
3. `authenticate()` validates fully, raises `AuthenticationException` with a generic message and
   the correct `scheme` for `WWW-Authenticate`, and returns a `SecurityPrincipal` with
   `authentication_type=self.name`.
4. Register it in the provider list. No middleware changes.
5. Add tests: valid, invalid, missing, ambiguous-with-other-provider.
6. Declare its header(s) in `dependencies.py` for OpenAPI with an explicit, unique `scheme_name`
   (e.g. `APIKeyHeader(name="X-Secret-Key", scheme_name="SecretKey", auto_error=False)`). Every
   `APIKeyHeader` defaults to the name `APIKeyHeader`, so a second one silently replaces the first
   in the spec and Swagger's Authorize dialog can't send all the headers. Test that every header
   appears in `components.securitySchemes`.

## 6. Security middleware

```python
import logging
from collections.abc import Iterable

from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from security.exceptions import AuthenticationException
from security.inbound.authentication_manager import AuthenticationManager
from security.inbound.context_holder import SecurityContextHolder
from security.inbound.principal import SecurityContext

logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """Pure ASGI authentication middleware (the SecurityFilterChain equivalent).

    Runs outside FastAPI's exception handlers, so it builds 401 responses itself.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        authentication_manager: AuthenticationManager,
        public_paths: Iterable[str] = (),
    ) -> None:
        self.app = app
        self._manager = authentication_manager
        # "/health" matches exactly; "/docs/" matches the prefix.
        paths = tuple(public_paths)
        self._public_exact = frozenset(p for p in paths if not p.endswith("/"))
        self._public_prefixes = tuple(p for p in paths if p.endswith("/"))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        try:
            principal = await self._manager.authenticate(HTTPConnection(scope))
        except AuthenticationException as exc:
            # Invalid credentials are rejected even on public paths.
            logger.info("Authentication failed", extra={"path": scope.get("path")})
            await self._reject(scope, receive, send, exc)
            return

        if principal is None and not self._is_public(scope["path"]):
            await self._reject(scope, receive, send, AuthenticationException())
            return

        token = SecurityContextHolder.set_context(SecurityContext(principal))
        try:
            await self.app(scope, receive, send)
        finally:
            SecurityContextHolder.reset_context(token)

    def _is_public(self, path: str) -> bool:
        return path in self._public_exact or path.startswith(self._public_prefixes)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, exc: AuthenticationException) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        response = JSONResponse(
            {"error": "unauthorized", "detail": str(exc)},
            status_code=401,
            headers={"WWW-Authenticate": exc.scheme},
        )
        await response(scope, receive, send)
```

Public paths: exact (`"/health"`) or prefix when ending in `/` (`"/public/"`). FastAPI docs need
`"/docs"`, `"/redoc"`, `"/openapi.json"`, and `"/docs/oauth2-redirect"` if used — or disable docs
in production. Middleware order: call `configure_inbound_security` **before** adding
`CORSMiddleware` so CORS is outermost and answers preflight `OPTIONS` without credentials.

## 7. Authorization

### 7.1 Policies

Policies are small composable objects (`&`, `|`, `~`) with a description used in audit logs.

```python
from collections.abc import Callable

from security.inbound.principal import SecurityPrincipal


class Policy:
    """Composable authorization rule: `has_role("ADMIN") | has_authority("ORDER_DELETE")`."""

    __slots__ = ("_check", "description")

    def __init__(self, check: Callable[[SecurityPrincipal], bool], description: str) -> None:
        self._check = check
        self.description = description

    def __call__(self, principal: SecurityPrincipal) -> bool:
        return bool(self._check(principal))

    def __and__(self, other: "Policy") -> "Policy":
        return Policy(lambda p: self(p) and other(p), f"({self.description} and {other.description})")

    def __or__(self, other: "Policy") -> "Policy":
        return Policy(lambda p: self(p) or other(p), f"({self.description} or {other.description})")

    def __invert__(self) -> "Policy":
        return Policy(lambda p: not self(p), f"not {self.description}")

    def __repr__(self) -> str:
        return f"Policy({self.description})"


def is_authenticated() -> Policy:
    return Policy(lambda p: True, "is_authenticated")


def has_authority(authority: str) -> Policy:
    return Policy(lambda p: authority in p.authorities, f"has_authority({authority!r})")


def has_any_authority(*authorities: str) -> Policy:
    required = frozenset(authorities)
    return Policy(lambda p: bool(required & p.authorities), f"has_any_authority{authorities!r}")


def has_all_authorities(*authorities: str) -> Policy:
    required = frozenset(authorities)
    return Policy(lambda p: required <= p.authorities, f"has_all_authorities{authorities!r}")


def has_role(role: str) -> Policy:
    return Policy(lambda p: role in p.roles, f"has_role({role!r})")


def has_any_role(*roles: str) -> Policy:
    required = frozenset(roles)
    return Policy(lambda p: bool(required & p.roles), f"has_any_role{roles!r}")


def belongs_to_tenant(tenant_id: str) -> Policy:
    return Policy(lambda p: p.tenant_id is not None and p.tenant_id == tenant_id, f"belongs_to_tenant({tenant_id!r})")
```

Authorities are granular permissions (`ORDER_READ`); roles group them (`ADMIN`). Prefer
authorities for decisions. If your IdP only issues roles, map roles → authorities in the provider
(`ROLE_AUTHORITIES = {"ADMIN": {...}}`) so endpoints check authorities.

### 7.2 The single enforcement point

```python
import logging

from security.exceptions import AuthorizationException
from security.inbound.context_holder import SecurityContextHolder
from security.inbound.policies import Policy
from security.inbound.principal import SecurityPrincipal

logger = logging.getLogger(__name__)


def authorize(policy: Policy) -> SecurityPrincipal:
    """Single enforcement point (AuthorizationManager) used by decorators and dependencies.

    Raises AuthenticationException (401) when anonymous, AuthorizationException (403) when denied.
    """
    principal = SecurityContextHolder.require_principal()
    if not policy(principal):
        logger.warning("Authorization denied", extra={"subject": principal.subject, "policy": policy.description})
        raise AuthorizationException()
    return principal
```

### 7.3 Decorators (service layer)

```python
import functools
import inspect
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar

from security.exceptions import AuthorizationException
from security.inbound.authorization import authorize
from security.inbound.context_holder import SecurityContextHolder
from security.inbound.policies import Policy, has_any_authority, has_any_role
from security.inbound.principal import SecurityPrincipal

P = ParamSpec("P")
R = TypeVar("R")


def _reject_generators(func: Callable[..., Any]) -> None:
    if inspect.isgeneratorfunction(func) or inspect.isasyncgenfunction(func):
        raise TypeError(f"Security decorators do not support generator functions: {func.__qualname__}")


def pre_authorize(policy: Policy) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Check `policy` against the current principal before the call (sync or async)."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        _reject_generators(func)
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                authorize(policy)
                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            authorize(policy)
            return func(*args, **kwargs)

        return sync_wrapper

    return decorator


def secured(*names: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Spring @Secured: allowed when the principal has ANY of the given roles or authorities."""
    if not names:
        raise ValueError("secured() requires at least one role or authority")
    return pre_authorize(has_any_role(*names) | has_any_authority(*names))


def post_authorize(
    check: Callable[[SecurityPrincipal, Any], bool],
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Run the method, then verify `check(principal, result)` before returning it.

    The method runs (side effects happen) even when access is denied, so only use this on
    reads, and still filter queries by tenant/owner; this is defence in depth, not a filter.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        _reject_generators(func)

        def verify(result: Any) -> None:
            if not check(SecurityContextHolder.require_principal(), result):
                raise AuthorizationException()

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                SecurityContextHolder.require_principal()
                result = await func(*args, **kwargs)
                verify(result)
                return result

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            SecurityContextHolder.require_principal()
            result = func(*args, **kwargs)
            verify(result)
            return result

        return sync_wrapper

    return decorator
```

```python
class OrderService:
    @pre_authorize(has_authority("ORDER_READ"))
    async def list_orders(self) -> list[Order]:
        principal = SecurityContextHolder.require_principal()
        return await self._repo.find_by_tenant(principal.tenant_id)   # still filter by tenant!

    @secured("ADMIN")
    async def purge(self) -> None: ...

    @post_authorize(lambda principal, order: order.owner_id == principal.subject)
    async def get_order(self, order_id: str) -> Order: ...
```

### 7.4 FastAPI dependencies (HTTP boundary)

```python
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends
from fastapi.security import APIKeyHeader, HTTPBearer

from security.inbound.authorization import authorize
from security.inbound.context_holder import SecurityContextHolder
from security.inbound.policies import Policy, has_all_authorities, has_any_role
from security.inbound.principal import SecurityPrincipal

# Declared only so OpenAPI / Swagger shows the security schemes. Authentication itself is
# done by SecurityMiddleware; auto_error=False keeps these schemes from enforcing anything.
_bearer_scheme = HTTPBearer(auto_error=False)
_api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


# Dependencies are async on purpose: sync dependencies run in a worker thread.
async def get_current_principal(
    _bearer: Annotated[object, Depends(_bearer_scheme)] = None,
    _api_key: Annotated[object, Depends(_api_key_scheme)] = None,
) -> SecurityPrincipal:
    return SecurityContextHolder.require_principal()


async def get_optional_principal() -> SecurityPrincipal | None:
    return SecurityContextHolder.get_principal()


CurrentPrincipal = Annotated[SecurityPrincipal, Depends(get_current_principal)]
OptionalPrincipal = Annotated[SecurityPrincipal | None, Depends(get_optional_principal)]


def require(policy: Policy) -> Callable[..., Awaitable[SecurityPrincipal]]:
    """Endpoint guard: `Depends(require(has_role("ADMIN")))` or in `dependencies=[...]`."""

    async def dependency(_: CurrentPrincipal) -> SecurityPrincipal:
        return authorize(policy)

    return dependency


def require_authority(*authorities: str) -> Callable[..., Awaitable[SecurityPrincipal]]:
    """All listed authorities are required."""
    return require(has_all_authorities(*authorities))


def require_role(*roles: str) -> Callable[..., Awaitable[SecurityPrincipal]]:
    """Any listed role is sufficient."""
    return require(has_any_role(*roles))
```

```python
@router.get("/orders", dependencies=[Depends(require_authority("ORDER_READ"))])
async def list_orders(principal: CurrentPrincipal) -> list[OrderOut]: ...

@router.delete("/orders/{order_id}")
async def delete_order(order_id: str, _: Annotated[SecurityPrincipal, Depends(require(has_role("ADMIN")))]): ...

# Whole router:
admin = APIRouter(prefix="/admin", dependencies=[Depends(require_role("ADMIN"))])
```

| Requirement | Use |
|---|---|
| Protect an HTTP endpoint / router | `Depends(require(...))` |
| Inject the caller | `CurrentPrincipal` / `OptionalPrincipal` |
| Protect a service method (any caller: HTTP, consumer, job) | `@pre_authorize` / `@secured` |
| Check ownership of a returned object | `@post_authorize` (plus query filtering) |
| Resource/tenant checks depending on arguments | explicit check in the service using `require_principal()`, raising `AuthorizationException` |

Prefer dependencies over decorators on route functions: they keep FastAPI's signature handling
and OpenAPI intact.

### 7.5 Object-level & tenant authorization

RBAC does not stop IDOR. Every query that returns tenant/user-owned data must be filtered by
`principal.tenant_id` / `principal.subject` *in the query*. Return 404 rather than 403 for objects
the caller may not know exist.

## 8. Exception handlers

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from security.exceptions import AuthenticationException, AuthorizationException


async def _authentication_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AuthenticationException)
    return JSONResponse(
        {"error": "unauthorized", "detail": str(exc)},
        status_code=401,
        headers={"WWW-Authenticate": exc.scheme},
    )


async def _authorization_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse({"error": "forbidden", "detail": "Access denied"}, status_code=403)


def install_security_exception_handlers(app: FastAPI) -> None:
    """Map security exceptions raised in endpoints, dependencies and services to 401/403."""
    app.add_exception_handler(AuthenticationException, _authentication_handler)
    app.add_exception_handler(AuthorizationException, _authorization_handler)
```

401 → `WWW-Authenticate` challenge with the scheme. 403 → generic body. Never echo the
reason a token failed (expired vs bad signature) to the client; log the exception class instead.

## 9. Logging rules (inbound)

Log: auth success (subject, auth type), auth failure (path, failure class), authorization
denied (subject, policy description). Never log: `Authorization` header, tokens, API keys,
passwords, full claims. Use `extra={...}` structured fields.
