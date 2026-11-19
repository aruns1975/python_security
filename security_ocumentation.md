# Security Architecture for Python FastAPI Applications
## Inbound Authentication, Authorization and Outbound Service Security

**Technology:** Python, FastAPI, ASGI, HTTPX  
**Architectural reference:** Spring Security

---

## 1. Introduction

The objective is to build a reusable, centralized security framework for Python applications using FastAPI.

The framework should provide two complementary capabilities:

1. **Inbound Security:** Secure incoming requests by authenticating users or services, establishing their security identity, and enforcing authorization rules.
2. **Outbound Security:** Secure outgoing API calls by automatically applying the appropriate authentication mechanism based on the target service.

The application business logic should not need to implement authentication or authorization repeatedly. Security should be handled by reusable infrastructure components.

The design follows the principles of Spring Security while using Python-native capabilities and FastAPI conventions.

### 1.1 Design principles

- Centralized authentication and authorization.
- Pluggable authentication mechanisms.
- Request-scoped security context.
- Declarative authorization using decorators and dependencies.
- Reusable outbound HTTP client.
- Pluggable authentication interceptors.
- Separation of business logic and security implementation.
- Safe handling of credentials and tokens.
- Support for asynchronous execution and concurrent requests.

---

# 2. Overall Architecture

The framework consists of two independent security pipelines.

### 2.1 Inbound Security Architecture

```text
                  INCOMING HTTP REQUEST
                           |
                           v
                 FastAPI / ASGI Server
                           |
                           v
                  Security Middleware
                           |
                           v
                  Authentication Manager
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
           JWT         API Key       Basic Auth
        Provider      Provider       Provider
             |             |             |
             +-------------+-------------+
                           |
                           v
                  Security Principal
                           |
                           v
                  Security Context
                           |
                           v
                 Authorization Layer
                           |
                +----------+----------+
                |                     |
                v                     v
           Decorators             FastAPI
           @pre_authorize         Dependencies
                |                     |
                +----------+----------+
                           |
                           v
                    Business Logic
                           |
                           v
                       Response
```

### 2.2 Outbound Security Architecture

```text
                 APPLICATION SERVICE
                           |
                           v
                    Service Client
                           |
                           v
                  Secure HTTP Client
                           |
                           v
                 Interceptor Manager
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
          API Key       Basic Auth      OAuth2
         Interceptor   Interceptor    Interceptor
             |             |             |
             +-------------+-------------+
                           |
                           v
                    HTTPX AsyncClient
                           |
                           v
                    EXTERNAL API
```

The two pipelines are independent but share the same architectural principle: security is implemented centrally and applied consistently.

---

# 3. Inbound Security

## 3.1 Objective

Inbound security is responsible for authenticating and authorizing incoming HTTP requests.

The application should support multiple authentication mechanisms without requiring endpoint implementations to understand how authentication works.

Potential authentication mechanisms include:

- JWT Bearer Token
- API Key
- HTTP Basic Authentication
- OAuth2 access tokens
- Additional custom authentication mechanisms in the future

The framework should allow new authentication providers to be registered without changing the core security middleware.

## 3.2 Core Components

The inbound security implementation consists of the following components.

| Component | Responsibility |
|---|---|
| SecurityMiddleware | Intercepts incoming HTTP requests |
| AuthenticationManager | Selects and invokes authentication providers |
| AuthenticationProvider | Implements a specific authentication mechanism |
| SecurityPrincipal | Represents the authenticated identity |
| SecurityContext | Holds authentication information |
| SecurityContextHolder | Provides access to the current security context |
| AuthorizationManager | Evaluates authorization policies |
| Security Decorators | Provides declarative authorization |
| FastAPI Dependencies | Injects identity and enforces endpoint access |
| Exception Handlers | Converts security exceptions into HTTP responses |

---

## 3.3 Security Middleware

The security middleware is the central entry point for inbound security.

It should execute before the request reaches the application endpoint.

Its responsibilities are:

1. Read the incoming HTTP request.
2. Identify the authentication mechanism.
3. Delegate authentication to the appropriate provider.
4. Obtain the authenticated principal.
5. Create a SecurityContext.
6. Store the context for the lifetime of the request.
7. Allow the request to continue.
8. Clean up the context after request processing.

A custom **pure ASGI middleware** is recommended for this implementation.

FastAPI's `BaseHTTPMiddleware` is convenient for simpler middleware, but pure ASGI middleware gives better control over asynchronous execution and context propagation.

### Middleware flow

```text
Request received
       |
       v
Extract authentication credentials
       |
       v
AuthenticationManager
       |
       v
AuthenticationProvider
       |
       v
Validate credentials
       |
       v
Create SecurityPrincipal
       |
       v
Create SecurityContext
       |
       v
Set SecurityContextHolder
       |
       v
Continue request processing
       |
       v
Reset SecurityContextHolder
       |
       v
Return response
```

The middleware should use `try/finally` to ensure the security context is always reset, including when an exception occurs.

---

## 3.4 Authentication Manager and Providers

Authentication should be implemented using a provider-based architecture.

Instead of putting JWT, API Key, and Basic Authentication logic inside the middleware, each mechanism should have its own provider.

### Authentication Provider Interface

```python
from abc import ABC, abstractmethod

class AuthenticationProvider(ABC):

    @abstractmethod
    def supports(self, request) -> bool:
        pass

    @abstractmethod
    async def authenticate(self, request):
        pass
```

Each provider implements the same interface.

For example:

```python
class JwtAuthenticationProvider(AuthenticationProvider):

    def supports(self, request) -> bool:
        return request.headers.get("Authorization", "").startswith("Bearer ")

    async def authenticate(self, request):
        # Extract JWT
        # Validate signature, issuer, audience and expiry
        # Extract claims
        # Construct SecurityPrincipal
        pass
```

Similarly:

```python
class ApiKeyAuthenticationProvider(AuthenticationProvider):

    def supports(self, request) -> bool:
        return "X-API-Key" in request.headers

    async def authenticate(self, request):
        # Extract API key
        # Validate against configured credential store
        # Construct SecurityPrincipal
        pass
```

Basic Authentication can be implemented using another provider.

### Authentication Manager

The AuthenticationManager maintains a list of registered providers.

```python
class AuthenticationManager:

    def __init__(self, providers):
        self.providers = providers

    async def authenticate(self, request):

        matching_providers = [
            provider
            for provider in self.providers
            if provider.supports(request)
        ]

        if not matching_providers:
            raise AuthenticationException(
                "No supported authentication mechanism"
            )

        if len(matching_providers) > 1:
            raise AuthenticationException(
                "Ambiguous authentication mechanism"
            )

        return await matching_providers[0].authenticate(request)
```

For a production implementation, provider selection should be deterministic and explicitly configured. If multiple authentication methods are intentionally supported for a request, the selection policy should define which one takes precedence.

### Important considerations

- Never trust a JWT without validating its signature and required claims.
- Validate issuer, audience, expiration and applicable token constraints.
- Store API keys securely, preferably as hashes where appropriate.
- Do not log passwords, API keys or access tokens.
- Use TLS for credential transmission.
- Define how anonymous endpoints are handled.

---

# 4. Security Principal and Security Context

Once authentication succeeds, the framework needs to store the identity of the authenticated user or service.

This is where the SecurityPrincipal and SecurityContext come into the picture.

## 4.1 Security Principal

The SecurityPrincipal represents the authenticated identity.

A possible implementation:

```python
from dataclasses import dataclass, field

@dataclass(frozen=True)
class SecurityPrincipal:

    subject: str
    username: str | None = None

    authorities: frozenset[str] = field(
        default_factory=frozenset
    )

    roles: frozenset[str] = field(
        default_factory=frozenset
    )

    claims: dict = field(default_factory=dict)

    authentication_type: str | None = None
    authenticated: bool = True
```

Example principal:

```python
SecurityPrincipal(
    subject="user123",
    username="john",
    authorities=frozenset({
        "ORDER_READ",
        "ORDER_CREATE"
    }),
    roles=frozenset({
        "ADMIN"
    }),
    authentication_type="JWT"
)
```

The principal should be treated as immutable after creation. Its claims should also be copied or exposed through an immutable representation if strict immutability is required.

## 4.2 Security Context

The SecurityContext represents the security information associated with the current request.

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class SecurityContext:

    principal: SecurityPrincipal | None

    authenticated: bool = False

    authentication_type: str | None = None
```

The SecurityContext is created after successful authentication.

## 4.3 SecurityContextHolder

In Java Spring Security, we commonly access the authenticated identity through:

```java
SecurityContextHolder
    .getContext()
    .getAuthentication()
    .getPrincipal();
```

We want an equivalent experience in Python.

However, Python asynchronous applications need special care because multiple requests can execute concurrently on the same thread.

Using a global variable or `threading.local()` is not appropriate for this purpose.

### Use Python ContextVar

Python provides `contextvars.ContextVar`, which is designed for asynchronous execution contexts.

```python
from contextvars import ContextVar

_security_context = ContextVar(
    "security_context",
    default=None
)
```

Create a facade:

```python
class SecurityContextHolder:

    @staticmethod
    def get_context():
        return _security_context.get()

    @staticmethod
    def get_principal():

        context = _security_context.get()

        if context is None:
            return None

        return context.principal

    @staticmethod
    def set_context(context):
        return _security_context.set(context)

    @staticmethod
    def reset_context(token):
        _security_context.reset(token)
```

### Usage inside application code

```python
principal = SecurityContextHolder.get_principal()

print(principal.username)
print(principal.authorities)
```

The application does not need to pass the principal through every service method.

This provides an experience similar to Spring's SecurityContextHolder.

## 4.4 Why ContextVar?

Consider two requests arriving simultaneously:

```text
Request A                         Request B
---------                         ---------
User: John                        User: Mary
   |                                 |
   v                                 v
Security Context A               Security Context B
   |                                 |
   v                                 v
Async execution A                Async execution B
   |                                 |
   v                                 v
Principal: John                  Principal: Mary
```

Both requests may execute on the same thread.

A normal global variable could cause one request to overwrite another request's identity.

`ContextVar` maintains values per execution context, preventing this kind of cross-request contamination during normal asynchronous execution.

### Context propagation considerations

- Context propagates through ordinary `await` operations.
- Newly created asyncio tasks inherit a copy of the current context.
- A child task changing its context does not change the parent task's context.
- `asyncio.to_thread()` propagates the current context.
- Direct executor usage may require `contextvars.copy_context()`.
- Background tasks should not accidentally inherit a request's security identity.

The middleware must always reset the context using the token returned by `ContextVar.set()`.

---

# 5. Authorization

Authentication answers:

**Who is making the request?**

Authorization answers:

**Is this identity allowed to perform the requested operation?**

Authorization should be centralized rather than implemented repeatedly inside endpoint business logic.

The framework should support:

1. Authority-based authorization.
2. Role-based authorization.
3. Multiple-authority checks.
4. Custom authorization policies.
5. Declarative decorators.
6. FastAPI dependency-based authorization.

## 5.1 Authorities and Roles

Authorities represent specific permissions.

Examples:

```text
ORDER_READ
ORDER_CREATE
ORDER_UPDATE
ORDER_DELETE
USER_READ
USER_ADMIN
```

Roles represent groups of permissions.

Examples:

```text
ADMIN
MANAGER
CUSTOMER
```

A role can be mapped to one or more authorities.

For example:

```text
ADMIN
  |
  +-- ORDER_READ
  +-- ORDER_CREATE
  +-- ORDER_UPDATE
  +-- ORDER_DELETE
  +-- USER_READ
  +-- USER_ADMIN
```

For authorization decisions, authorities provide more granular control.

---

# 6. Declarative Security Using Python Decorators

Spring Security provides annotations such as:

```java
@PreAuthorize("hasAuthority('ORDER_READ')")
```

Python does not have Java-style annotations, but decorators provide a similar programming model.

We can implement:

```python
@pre_authorize(...)
@secured(...)
@post_authorize(...)
```

## 6.1 Authority policy functions

Start with reusable policy functions.

```python
def has_authority(authority):

    def policy(principal):

        return authority in principal.authorities

    return policy


def has_role(role):

    def policy(principal):

        return role in principal.roles

    return policy


def has_any_authority(*authorities):

    def policy(principal):

        return bool(
            set(authorities) & principal.authorities
        )

    return policy


def has_all_authorities(*authorities):

    def policy(principal):

        return set(authorities).issubset(
            principal.authorities
        )

    return policy
```

## 6.2 PreAuthorize decorator

The `pre_authorize` decorator checks authorization before executing the method.

```python
from functools import wraps
import inspect

def pre_authorize(policy):

    def decorator(func):

        if inspect.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args, **kwargs):

                principal = (
                    SecurityContextHolder.get_principal()
                )

                if principal is None:
                    raise AuthenticationException(
                        "Authentication required"
                    )

                if not policy(principal):
                    raise AuthorizationException(
                        "Access denied"
                    )

                return await func(*args, **kwargs)

            return async_wrapper

        @wraps(func)
        def sync_wrapper(*args, **kwargs):

            principal = (
                SecurityContextHolder.get_principal()
            )

            if principal is None:
                raise AuthenticationException(
                    "Authentication required"
                )

            if not policy(principal):
                raise AuthorizationException(
                    "Access denied"
                )

            return func(*args, **kwargs)

        return sync_wrapper

    return decorator
```

## 6.3 Using the decorator

```python
class OrderService:

    @pre_authorize(has_authority("ORDER_READ"))
    async def get_orders(self):

        return await self.repository.find_all()

    @pre_authorize(has_authority("ORDER_CREATE"))
    async def create_order(self, order):

        return await self.repository.save(order)

    @pre_authorize(has_role("ADMIN"))
    async def delete_order(self, order_id):

        return await self.repository.delete(order_id)
```

The service does not need to manually inspect the principal or check permissions.

The decorator handles authorization automatically.

## 6.4 Additional authorization decorators

The framework can also support:

### `@secured`

For simpler role or authority checks:

```python
@secured("ADMIN")
async def delete_user(user_id):
    pass
```

### `@post_authorize`

For checking access after the method executes:

```python
@post_authorize(...)
async def get_order(order_id):
    pass
```

A post-authorization implementation needs access to the method result and should support both synchronous and asynchronous methods.

Use post-authorization carefully. It does not replace filtering database queries by tenant or user ownership. Sensitive records should be filtered before they are retrieved or returned.

## 6.5 FastAPI Dependencies

FastAPI dependencies are another important part of the authorization design.

They are particularly useful at the HTTP endpoint boundary because they integrate with FastAPI's dependency injection and OpenAPI documentation.

Example:

```python
from fastapi import Depends

def get_current_principal():

    principal = SecurityContextHolder.get_principal()

    if principal is None:
        raise AuthenticationException(
            "Authentication required"
        )

    return principal
```

An endpoint can inject the principal explicitly:

```python
@app.get("/orders")
async def get_orders(
    principal = Depends(get_current_principal)
):

    return await order_service.get_orders()
```

A reusable dependency can also enforce an authority:

```python
def require_authority(authority):

    async def dependency(
        principal = Depends(get_current_principal)
    ):

        if authority not in principal.authorities:
            raise AuthorizationException(
                "Access denied"
            )

        return principal

    return dependency
```

Usage:

```python
@app.post("/orders")
async def create_order(
    principal = Depends(
        require_authority("ORDER_CREATE")
    )
):

    return await order_service.create_order()
```

### When to use decorators versus dependencies?

| Requirement | Recommended approach |
|---|---|
| Protect service methods | Decorators |
| Protect HTTP endpoints | FastAPI dependencies |
| Inject current principal | FastAPI dependencies |
| Reuse authorization policies | Policy functions |
| Validate returned object access | Post-authorization |

For FastAPI route functions, dependencies are generally preferable to custom decorators because they preserve FastAPI's normal parameter and OpenAPI handling.

---

# 7. Exception Handling

Security exceptions should be handled centrally.

The application should not need to convert authentication or authorization failures into HTTP responses individually.

Define two exception types:

```python
class AuthenticationException(Exception):
    pass


class AuthorizationException(Exception):
    pass
```

Map them centrally:

| Exception | HTTP Status | Meaning |
|---|---:|---|
| AuthenticationException | 401 | Authentication failed or is required |
| AuthorizationException | 403 | Authenticated identity lacks permission |

Example:

```python
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception_handler(AuthenticationException)
async def authentication_exception_handler(
    request: Request,
    exc: AuthenticationException
):

    return JSONResponse(
        status_code=401,
        content={"detail": str(exc)}
    )


@app.exception_handler(AuthorizationException)
async def authorization_exception_handler(
    request: Request,
    exc: AuthorizationException
):

    return JSONResponse(
        status_code=403,
        content={"detail": str(exc)}
    )
```

A 401 response should include an appropriate `WWW-Authenticate` challenge when required by the authentication scheme.

---

# 8. Outbound Security

## 8.1 Objective

Outbound security handles authentication when the application calls external services.

For example, the application may communicate with:

| External Service | Authentication |
|---|---|
| Service A | API Key |
| Service B | Basic Authentication |
| Service C | OAuth2 Bearer Token |
| Service D | Custom authentication |

The application should not need to implement these authentication mechanisms in every API call.

Instead, authentication should be handled through a reusable HTTP client and interceptor architecture.

## 8.2 Desired application experience

The application should be able to call another API like this:

```python
response = await billing_client.get(
    "/v1/invoices"
)
```

Or:

```python
response = await inventory_client.post(
    "/v1/stock",
    json=payload
)
```

The business logic should not know:

- Whether the service uses API Key authentication.
- Whether it uses Basic Authentication.
- Whether it requires OAuth2.
- How credentials are retrieved.
- How tokens are refreshed.
- Which headers must be attached.

All these concerns should be handled by the outbound security framework.

---

# 9. Outbound Security Components

| Component | Responsibility |
|---|---|
| Service Registry | Stores external service configurations |
| Service Client | Provides a service-specific API |
| SecureHttpClient | Central HTTP communication layer |
| Interceptor Manager | Executes registered interceptors |
| Authentication Interceptor | Adds authentication credentials |
| API Key Interceptor | Adds API Key headers |
| Basic Auth Interceptor | Applies Basic Authentication |
| OAuth2 Interceptor | Adds Bearer tokens |
| Token Provider | Retrieves, caches and refreshes tokens |
| HTTPX AsyncClient | Executes actual HTTP requests |

## 9.1 Service Registry

Maintain a centralized configuration for external services.

Example:

```python
SERVICES = {
    "SERVICE_A": {
        "base_url": "https://service-a.example.com",
        "auth_type": "API_KEY"
    },

    "SERVICE_B": {
        "base_url": "https://service-b.example.com",
        "auth_type": "BASIC"
    },

    "SERVICE_C": {
        "base_url": "https://service-c.example.com",
        "auth_type": "OAUTH2"
    }
}
```

Credentials should not be stored directly in this configuration.

They should be retrieved from a secure configuration provider or secrets manager.

The registry should contain service metadata, not hardcoded secrets.

---

# 10. Outbound Interceptor Architecture

An interceptor is a component that can inspect or modify an outgoing HTTP request before it is sent.

The framework should support multiple registered interceptors.

Each interceptor determines whether it applies to the target service.

## 10.1 Interceptor Interface

```python
from abc import ABC, abstractmethod

class RequestInterceptor(ABC):

    @abstractmethod
    def supports(self, context) -> bool:
        pass

    @abstractmethod
    async def intercept(self, context):
        pass
```

The request context can contain:

```python
from dataclasses import dataclass, field
import httpx

@dataclass
class RequestContext:

    service_id: str

    request: httpx.Request

    attributes: dict = field(
        default_factory=dict
    )
```

## 10.2 API Key Interceptor

Suppose Service A requires an API Key.

```python
class ApiKeyInterceptor(RequestInterceptor):

    def __init__(self, credential_provider):
        self.credential_provider = credential_provider

    def supports(self, context):

        return context.service_id == "SERVICE_A"

    async def intercept(self, context):

        api_key = await (
            self.credential_provider.get_api_key(
                context.service_id
            )
        )

        context.request.headers["X-API-Key"] = api_key
```

Whenever the application calls Service A, this interceptor automatically attaches the API Key.

## 10.3 Basic Authentication Interceptor

Service B may require username and password.

Prefer HTTPX's built-in Basic Authentication implementation:

```python
class BasicAuthInterceptor(RequestInterceptor):

    def __init__(self, credential_provider):
        self.credential_provider = credential_provider

    def supports(self, context):

        return context.service_id == "SERVICE_B"

    async def intercept(self, context):

        username, password = await (
            self.credential_provider.get_basic_credentials(
                context.service_id
            )
        )

        import base64

        credentials = base64.b64encode(
            f"{username}:{password}".encode()
        ).decode()

        context.request.headers["Authorization"] = (
            f"Basic {credentials}"
        )
```

An alternative is to use `httpx.BasicAuth` as the authentication mechanism when sending the request. This is preferable when using HTTPX's native authentication flow directly.

Credentials must be transmitted only over HTTPS.

## 10.4 OAuth2 Interceptor

Service C may require an OAuth2 Bearer token.

The interceptor should not be responsible for obtaining or refreshing tokens itself.

That responsibility belongs to a dedicated TokenProvider.

```python
class OAuth2Interceptor(RequestInterceptor):

    def __init__(self, token_provider):
        self.token_provider = token_provider

    def supports(self, context):

        return context.service_id == "SERVICE_C"

    async def intercept(self, context):

        token = await (
            self.token_provider.get_access_token(
                context.service_id
            )
        )

        context.request.headers["Authorization"] = (
            f"Bearer {token}"
        )
```

### Token Provider responsibilities

The TokenProvider should handle:

1. Obtaining access tokens.
2. Caching tokens.
3. Checking token expiration.
4. Refreshing expired or expiring tokens.
5. Preventing concurrent requests from unnecessarily refreshing the same token.
6. Handling token endpoint failures.
7. Keeping tokens isolated by service and client identity.

A token provider interface could look like this:

```python
from abc import ABC, abstractmethod

class TokenProvider(ABC):

    @abstractmethod
    async def get_access_token(
        self,
        service_id: str
    ) -> str:
        pass
```

The implementation can later support client credentials, authorization code, or other required OAuth2 flows.

---

# 11. Interceptor Manager

The InterceptorManager maintains all registered interceptors.

When a request is made:

1. The manager receives the request context.
2. It checks which interceptors support the target service.
3. It executes the applicable interceptors.
4. The resulting request is passed to the HTTP client.

Example:

```python
class InterceptorManager:

    def __init__(self):
        self.interceptors = []

    def register(self, interceptor):

        self.interceptors.append(interceptor)

    async def execute(self, context):

        for interceptor in self.interceptors:

            if interceptor.supports(context):

                await interceptor.intercept(context)

        return context
```

### Important architectural distinction

Not every interceptor should be treated as an authentication interceptor.

For example, the application may eventually have:

- Authentication interceptors.
- Correlation ID interceptors.
- Logging interceptors.
- Tracing interceptors.
- Request transformation interceptors.

Multiple generic interceptors should be allowed to execute on the same request.

However, there should normally be exactly one applicable authentication strategy for a service.

Therefore, the production implementation should distinguish authentication interceptors from general request interceptors and validate that the configured authentication strategy is unambiguous.

---

# 12. Secure HTTP Client

The SecureHttpClient is the central component that connects the interceptor framework with HTTPX.

The application should not instantiate HTTPX clients or attach authentication headers directly in business services.

A simplified implementation:

```python
import httpx

class SecureHttpClient:

    def __init__(
        self,
        http_client,
        service_registry,
        interceptor_manager
    ):

        self.http_client = http_client
        self.service_registry = service_registry
        self.interceptor_manager = interceptor_manager

    async def request(
        self,
        service_id,
        method,
        path,
        **kwargs
    ):

        service = self.service_registry[service_id]

        base_url = service["base_url"].rstrip("/") + "/"

        url = base_url + path.lstrip("/")

        request = self.http_client.build_request(
            method,
            url,
            **kwargs
        )

        context = RequestContext(
            service_id=service_id,
            request=request
        )

        await self.interceptor_manager.execute(context)

        response = await self.http_client.send(
            context.request,
            follow_redirects=False
        )

        response.raise_for_status()

        return response
```

This is an architectural starting point. A production implementation should additionally validate that the final URL belongs to the configured service origin, handle query parameters safely, define timeout and retry policies, and manage streaming responses.

The client should not allow arbitrary caller-provided URLs to bypass the registered service configuration.

## 12.1 Service-specific clients

A further improvement is to avoid passing a service ID into every application call.

Instead, create a client bound to a particular service.

For example:

```python
class ServiceClient:

    def __init__(self, secure_client, service_id):
        self.secure_client = secure_client
        self.service_id = service_id

    async def get(self, path, **kwargs):

        return await self.secure_client.request(
            self.service_id,
            "GET",
            path,
            **kwargs
        )

    async def post(self, path, **kwargs):

        return await self.secure_client.request(
            self.service_id,
            "POST",
            path,
            **kwargs
        )

    async def put(self, path, **kwargs):

        return await self.secure_client.request(
            self.service_id,
            "PUT",
            path,
            **kwargs
        )

    async def delete(self, path, **kwargs):

        return await self.secure_client.request(
            self.service_id,
            "DELETE",
            path,
            **kwargs
        )
```

Application-specific clients can then be created:

```python
billing_client = ServiceClient(
    secure_http_client,
    "SERVICE_A"
)

inventory_client = ServiceClient(
    secure_http_client,
    "SERVICE_C"
)
```

Application code becomes:

```python
response = await billing_client.get(
    "/v1/invoices"
)
```

This is cleaner and safer because the application cannot accidentally select the wrong authentication configuration for a service.

---

# 13. HTTPX Client Lifecycle

The application should generally maintain a shared `httpx.AsyncClient` rather than creating a new client for every outgoing request.

A shared client provides connection pooling and more efficient resource management.

FastAPI lifespan can manage its lifecycle.

Example:

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
import httpx

@asynccontextmanager
async def lifespan(app: FastAPI):

    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=False
    ) as http_client:

        app.state.http_client = http_client

        # Initialize the service registry,
        # interceptors and secure HTTP client here.

        yield

app = FastAPI(lifespan=lifespan)
```

The actual initialization should create the interceptor manager, register the configured interceptors, and construct the SecureHttpClient.

The HTTPX client should be closed automatically when the application shuts down.

---

# 14. Security Configuration

Both inbound and outbound security should be configured centrally.

A possible configuration structure:

```yaml
security:

  inbound:

    enabled: true

    authentication:
      providers:
        - type: JWT
          enabled: true

        - type: API_KEY
          enabled: true

        - type: BASIC
          enabled: false

    authorization:
      enabled: true

  outbound:

    enabled: true

    services:

      SERVICE_A:
        base_url: https://service-a.example.com
        authentication:
          type: API_KEY
          credential_reference: service-a-api-key

      SERVICE_B:
        base_url: https://service-b.example.com
        authentication:
          type: BASIC
          credential_reference: service-b-basic-auth

      SERVICE_C:
        base_url: https://service-c.example.com
        authentication:
          type: OAUTH2
          credential_reference: service-c-oauth
```

This configuration is illustrative. Secrets should be resolved from a secrets manager or secure credential provider rather than embedded in the YAML file.

The framework should support registering providers and interceptors through dependency injection or an application-level factory.

---

# 15. Production Security Considerations

The framework should account for the following concerns before being used in production.

## 15.1 Inbound Security

- Validate JWT signatures and all required claims.
- Validate token issuer and audience.
- Enforce token expiration.
- Use secure credential storage.
- Avoid logging credentials or tokens.
- Define anonymous endpoint behavior explicitly.
- Reset the ContextVar in all execution paths.
- Avoid mutable shared principal state.
- Apply tenant and resource-level authorization where required.
- Protect sensitive operations against privilege escalation.
- Consider rate limiting and brute-force protection for credential-based authentication.

## 15.2 Outbound Security

- Use HTTPS for all credential-bearing requests.
- Store secrets outside source code.
- Validate the destination host against the registered service.
- Disable redirects by default when credentials are attached.
- Never forward credentials to an untrusted redirect destination.
- Avoid accidental overwriting of authentication headers.
- Cache OAuth2 tokens securely.
- Handle concurrent token refresh safely.
- Define connection and read timeouts.
- Apply controlled retries only where appropriate.
- Avoid retrying non-idempotent operations without an explicit idempotency strategy.
- Ensure credentials for one service cannot be reused with another service.

## 15.3 Logging and Observability

Security-related logs should include useful operational information without exposing secrets.

Examples:

```text
Authentication successful
Authentication failed
Authorization denied
Outbound request initiated
Outbound authentication strategy selected
Outbound request failed
OAuth2 token refreshed
```

Never log:

- Passwords.
- API keys.
- Full JWTs.
- OAuth2 access or refresh tokens.
- Authorization headers.

Correlation IDs and distributed tracing should be supported through separate request/response interceptors.

---

# 16. Mapping Spring Security to Python

The following table maps familiar Spring Security concepts to the proposed Python implementation.

| Spring Security | Python Implementation |
|---|---|
| SecurityFilterChain | ASGI security middleware pipeline |
| OncePerRequestFilter | Custom ASGI middleware |
| AuthenticationManager | AuthenticationManager |
| AuthenticationProvider | AuthenticationProvider |
| Authentication | SecurityPrincipal / authentication result |
| SecurityContext | SecurityContext |
| SecurityContextHolder | ContextVar-backed SecurityContextHolder |
| GrantedAuthority | Authority |
| Role | Role |
| @PreAuthorize | @pre_authorize |
| @PostAuthorize | @post_authorize |
| @Secured | @secured |
| AccessDeniedException | AuthorizationException |
| AuthenticationException | AuthenticationException |
| RestTemplate interceptor | HTTPX request interceptor |
| WebClient filters | HTTPX client/interceptor pipeline |

The intention is not to reproduce Spring Security internally, but to provide a similar programming experience using Python's native asynchronous execution model.

---

# 17. Recommended Project Structure

A suggested reusable package structure:

```text
application/
│
├── main.py
│
├── security/
│   │
│   ├── inbound/
│   │   ├── middleware.py
│   │   ├── authentication_manager.py
│   │   ├── authentication_provider.py
│   │   ├── jwt_provider.py
│   │   ├── api_key_provider.py
│   │   ├── basic_auth_provider.py
│   │   ├── principal.py
│   │   ├── security_context.py
│   │   ├── security_context_holder.py
│   │   ├── authorization_manager.py
│   │   ├── decorators.py
│   │   ├── dependencies.py
│   │   └── exceptions.py
│   │
│   ├── outbound/
│   │   ├── secure_http_client.py
│   │   ├── service_client.py
│   │   ├── service_registry.py
│   │   ├── request_context.py
│   │   ├── interceptor_manager.py
│   │   ├── interceptors/
│   │   │   ├── base.py
│   │   │   ├── api_key.py
│   │   │   ├── basic_auth.py
│   │   │   ├── oauth2.py
│   │   │   ├── correlation_id.py
│   │   │   └── logging.py
│   │   ├── token_provider.py
│   │   └── credential_provider.py
│   │
│   ├── configuration.py
│   └── exceptions.py
│
├── services/
│   ├── order_service.py
│   └── inventory_service.py
│
├── repositories/
│
└── api/
    └── routes/
```

The `security` package should be reusable across multiple FastAPI applications.

Application-specific policies, service registrations and credentials should be supplied by the consuming application.

---

# 18. End-to-End Examples

## 18.1 Inbound example

Suppose a user calls:

```http
GET /orders
Authorization: Bearer <JWT>
```

The processing flow is:

1. SecurityMiddleware receives the request.
2. AuthenticationManager selects JwtAuthenticationProvider.
3. The provider validates the JWT.
4. It creates a SecurityPrincipal with the user's identity and authorities.
5. SecurityMiddleware creates a SecurityContext.
6. SecurityContextHolder stores the context using ContextVar.
7. The request reaches the endpoint.
8. The endpoint or service applies its authorization policy.
9. The service executes only if authorization succeeds.
10. Middleware resets the security context after processing.

The application service can simply use:

```python
@pre_authorize(has_authority("ORDER_READ"))
async def get_orders():

    principal = SecurityContextHolder.get_principal()

    return await repository.find_orders(
        user_id=principal.subject
    )
```

## 18.2 Outbound example

Suppose the application needs to call Service C, which requires OAuth2.

The application executes:

```python
response = await inventory_client.get(
    "/v1/stock"
)
```

The processing flow is:

1. InventoryClient forwards the request to SecureHttpClient.
2. SecureHttpClient resolves the registered Service C configuration.
3. InterceptorManager evaluates the registered interceptors.
4. OAuth2Interceptor identifies that it supports Service C.
5. OAuth2Interceptor requests a token from TokenProvider.
6. TokenProvider returns a valid cached token or obtains a new one.
7. OAuth2Interceptor attaches the Bearer token.
8. HTTPX sends the request.
9. The response is returned to the application.

The application does not need to know anything about OAuth2.

---

# 19. Implementation Roadmap

The framework should be developed incrementally.

| Phase | Implementation | Expected outcome |
|---|---|---|
| 1 | SecurityPrincipal and SecurityContext | Common identity model |
| 2 | ContextVar and SecurityContextHolder | Request-scoped identity |
| 3 | AuthenticationProvider and AuthenticationManager | Pluggable authentication |
| 4 | ASGI SecurityMiddleware | Centralized inbound authentication |
| 5 | Authorization policies and decorators | Declarative service authorization |
| 6 | FastAPI dependencies and exception handlers | Endpoint-level security |
| 7 | Service Registry and HTTPX wrapper | Centralized outbound communication |
| 8 | InterceptorManager and API Key/Basic interceptors | Pluggable outbound authentication |
| 9 | OAuth2 TokenProvider and interceptor | Token caching and refresh |
| 10 | Logging, tracing, testing and hardening | Production readiness |

### Testing requirements

The framework should include tests for:

- Successful and unsuccessful authentication.
- Each authentication provider.
- Concurrent requests with different principals.
- Security context cleanup after exceptions.
- Role and authority checks.
- Unauthorized and forbidden HTTP responses.
- Correct interceptor selection.
- Prevention of multiple conflicting authentication strategies.
- Correct credential isolation between services.
- OAuth2 token caching and concurrent refresh.
- Redirect and destination-host security.
- HTTP client lifecycle and resource cleanup.

---

# 20. Final Architectural Recommendation

The proposed framework should expose two simple interfaces to the application.

### Inbound

```python
principal = SecurityContextHolder.get_principal()
```

And declarative authorization:

```python
@pre_authorize(has_authority("ORDER_READ"))
async def get_orders():
    ...
```

For FastAPI endpoints, use dependencies where explicit principal injection or OpenAPI integration is required.

### Outbound

```python
response = await billing_client.get(
    "/v1/invoices"
)
```

The underlying framework automatically selects the appropriate authentication mechanism and applies the required credentials.

**The key architectural principle is that business logic should express what it wants to do, not how security is implemented.**

Inbound security determines who is calling and what they are allowed to do. Outbound security determines how the application securely communicates with other services.

Together, these components provide a reusable security foundation for multiple Python FastAPI applications, with an experience conceptually similar to Spring Security.