# Adding an outbound interceptor to mycaller-app

mycaller-app adds credentials to its outbound calls through **interceptors** inside
`SecureHttpClient`. Business code calls `client.get("/api/v1/orders")` and never handles a key.
This guide shows how to add:

- **An authentication interceptor**, for a downstream service that authenticates in a new way.
  The worked example is a static bearer token (`Authorization: Bearer <token>`).
- **A general interceptor**, for a non-secret header or other behaviour on every call. The worked
  example is `X-Caller-App`.
- **A new downstream service** that uses either.

Both worked examples were run against a copy of mycaller-app: 130 tests passed, and ruff and mypy
were clean.

## How interceptors fit in

```text
ServiceClient.get("/v1/prices")
  └─ SecureHttpClient
       ├─ registry lookup → ServiceConfig(service_id, base_url, auth_type, credential_ref)
       ├─ path + header checks (callers can't set Authorization, Cookie, Host or credential headers)
       ├─ InterceptorManager
       │    ├─ general interceptors, in `order` (CorrelationIdInterceptor -100, ...)   ← run first, never see secrets
       │    └─ exactly ONE authentication interceptor, chosen by service.auth_type      ← runs last
       ├─ destination check (https, registered origin)
       └─ send (no redirects, no cookies, proxy settings ignored)
```

| | Authentication interceptor | General interceptor |
|---|---|---|
| Base class | `AuthenticationInterceptor` | `RequestInterceptor` |
| How many run on a request | exactly one, chosen by the service's `auth_type` | all whose `supports()` is true, in `order` |
| May read secrets | yes, from `SecretStore` | **no** |
| Registered in | `outbound_security(..., auth_interceptors=[...])` | `outbound_security(..., interceptors=[...])` |

## Steps for a new authentication interceptor

| # | Step | File |
|---|---|---|
| 1 | Add an `AuthType` member | `security/outbound/service_registry.py` |
| 2 | If it uses a custom header, add a `ServiceConfig` field for the header name **and** include it in `credential_headers` (so callers can't set it) | `security/outbound/service_registry.py` |
| 3 | Write the interceptor (`auth_type = AuthType.<NEW>`, reads secrets with `SecretStore.get_secret(credential_ref, <key>)`) | `security/outbound/interceptors/<name>.py` |
| 4 | Declare its secret keys in `REQUIRED_SECRET_KEYS`, so a missing secret stops startup | `security/configuration.py` |
| 5 | Register it in `outbound_security()` under `auth_interceptors` | `security/configuration.py` |
| 6 | Register the service that uses it (next section) | `.env`, `scripts/generate_credentials.py` |
| 7 | Add tests (matrix below) | `tests/` |
| 8 | Run `uv run pytest -q`, `uv run ruff check .` and `uv run mypy .`, then `./app.sh restart` | |

Rules that keep the app secure:
- **Choose by `auth_type`, never by service id.** Two interceptors for the same `AuthType` make startup fail.
- **Overwrite the header; never append to a value the caller supplied.** `SecureHttpClient` already refuses caller-supplied credential headers.
- **Don't log the credential.** Don't put it in exception messages either.
- **Tokens that expire need a `TokenProvider`.** Don't fetch a token in `intercept()` on every call. The skill's OAuth2 client-credentials interceptor (`templates/security/outbound/interceptors/oauth2.py` and `token_provider.py`) caches tokens, refreshes them once under a lock, and implements `on_unauthorized()` to refresh and retry once on a 401.

## Worked example 1: a static bearer token (`AuthType.BEARER_TOKEN`)

### 1. Add the auth type: `security/outbound/service_registry.py`

```python
class AuthType(StrEnum):
    NONE = "NONE"
    API_KEY = "API_KEY"
    BASIC = "BASIC"
    OAUTH2_CLIENT_CREDENTIALS = "OAUTH2_CLIENT_CREDENTIALS"
    APP_CREDENTIALS = "APP_CREDENTIALS"  # X-Application-Id + X-Secret-Key
    BEARER_TOKEN = "BEARER_TOKEN"  # noqa: S105 - enum name, not a secret. Authorization: Bearer <token>
```

`Authorization` is already on the reserved list, so step 2 isn't needed here. For a custom header
such as `X-Partner-Token`, add a field like `partner_token_header: str = "X-Partner-Token"` and
include it in `credential_headers`, as `application_id_header` and `secret_key_header` are.

### 2. Write the interceptor: `security/outbound/interceptors/bearer_token.py`

```python
from security.outbound.credential_provider import SecretStore
from security.outbound.interceptors.base import AuthenticationInterceptor
from security.outbound.request_context import RequestContext
from security.outbound.service_registry import AuthType


class BearerTokenInterceptor(AuthenticationInterceptor):
    """Sends a static service token as `Authorization: Bearer <token>` (AuthType.BEARER_TOKEN).

    Secret-store key per credential_ref: `token`. For tokens that expire, use the OAuth2
    client-credentials interceptor and TokenProvider instead."""

    auth_type = AuthType.BEARER_TOKEN

    def __init__(self, secrets: SecretStore) -> None:
        self._secrets = secrets

    async def intercept(self, context: RequestContext) -> None:
        service = context.service
        assert service.credential_ref is not None  # guaranteed by ServiceConfig validation
        token = await self._secrets.get_secret(service.credential_ref, "token")
        context.request.headers["Authorization"] = f"Bearer {token}"
```

### 3. Declare its secrets and register it: `security/configuration.py`

```python
from security.outbound.interceptors.bearer_token import BearerTokenInterceptor

REQUIRED_SECRET_KEYS: Mapping[AuthType, tuple[str, ...]] = {
    AuthType.NONE: (),
    AuthType.API_KEY: ("api_key",),
    AuthType.APP_CREDENTIALS: ("application_id", "secret_key"),
    AuthType.BEARER_TOKEN: ("token",),
}
```

In `outbound_security()`:

```python
        interceptors = InterceptorManager(
            interceptors=[CorrelationIdInterceptor(), *extra_interceptors],
            auth_interceptors=[
                ApiKeyInterceptor(secrets),
                AppCredentialsInterceptor(secrets),
                BearerTokenInterceptor(secrets),
            ],
        )
```

If an `AuthType` has no registered interceptor, `InterceptorManager.validate()` makes startup fail
for any service configured with it.

### 4. Test it: `tests/test_bearer_token_interceptor.py`

```python
"""BEARER_TOKEN auth interceptor and the general CallerIdentityInterceptor."""

import httpx
import pytest

from security.configuration import OutboundSettings, outbound_security
from security.outbound.service_registry import AuthType, ServiceConfig

SECRETS = {("svc-p", "token"): "token-P", ("svc-a", "api_key"): "key-A"}


class FakeSecrets:
    async def get_secret(self, reference: str, key: str) -> str:
        try:
            return SECRETS[(reference, key)]
        except KeyError:
            raise LookupError(f"Secret not configured: {reference}/{key}") from None


SETTINGS = OutboundSettings(
    services={
        "PRICING": ServiceConfig(
            service_id="PRICING", base_url="https://pricing.example.com", auth_type=AuthType.BEARER_TOKEN, credential_ref="svc-p"
        ),
        "A": ServiceConfig(service_id="A", base_url="https://a.example.com", auth_type=AuthType.API_KEY, credential_ref="svc-a"),
    }
)


async def test_bearer_token_sent_only_to_its_service() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    async with outbound_security(SETTINGS, secrets=FakeSecrets(), transport=httpx.MockTransport(handler)) as outbound:
        await outbound.client_for("PRICING").get("/v1/prices")
        await outbound.client_for("A").get("/v1/x")

    pricing, other = seen
    assert pricing.headers["Authorization"] == "Bearer token-P" and "x-api-key" not in pricing.headers
    assert "authorization" not in other.headers and other.headers["X-API-Key"] == "key-A"
    # Only if you also add CallerIdentityInterceptor (worked example 2):
    assert pricing.headers["X-Caller-App"] == other.headers["X-Caller-App"] == "mycaller-app"


async def test_missing_token_fails_startup() -> None:
    settings = OutboundSettings(
        services={
            "PRICING": ServiceConfig(
                service_id="PRICING", base_url="https://pricing.example.com", auth_type=AuthType.BEARER_TOKEN, credential_ref="missing"
            )
        }
    )
    with pytest.raises(LookupError, match="missing/token"):
        async with outbound_security(settings, secrets=FakeSecrets()):
            pass


async def test_caller_cannot_override_authorization() -> None:
    from security.exceptions import OutboundSecurityException

    async with outbound_security(SETTINGS, secrets=FakeSecrets(), transport=httpx.MockTransport(lambda r: httpx.Response(200))) as outbound:
        with pytest.raises(OutboundSecurityException):
            await outbound.client_for("PRICING").get("/v1/prices", headers={"Authorization": "Bearer forged"})
```

## Worked example 2: a general interceptor (`X-Caller-App`)

General interceptors add non-secret behaviour to every call (or to the calls their `supports()`
selects). They run before authentication, so they can never read or log credentials.

`security/outbound/interceptors/caller_identity.py`:

```python
from security.outbound.interceptors.base import RequestInterceptor
from security.outbound.request_context import RequestContext


class CallerIdentityInterceptor(RequestInterceptor):
    """Adds a non-secret `X-Caller-App` header to every outbound request, for downstream
    logging. A general interceptor: it runs before authentication and never sees credentials."""

    order = 10  # after CorrelationIdInterceptor (-100)

    def __init__(self, app_name: str = "mycaller-app", header_name: str = "X-Caller-App") -> None:
        self._app_name = app_name
        self._header = header_name

    async def intercept(self, context: RequestContext) -> None:
        context.request.headers[self._header] = self._app_name
```

Register it in `outbound_security()` in `security/configuration.py`:

```python
from security.outbound.interceptors.caller_identity import CallerIdentityInterceptor
...
            interceptors=[CorrelationIdInterceptor(), CallerIdentityInterceptor(), *extra_interceptors],
```

To apply it to only some services, override `supports()`:

```python
    def supports(self, context: RequestContext) -> bool:
        return context.service_id in {"CALLED_APP", "PRICING_APP"}
```

Never give a general interceptor a `SecretStore`, and never let it set a credential header. That
is what authentication interceptors are for.

## Registering a new downstream service

Once its `AuthType` has an interceptor, adding a service that uses it is configuration plus a
typed client. Example: `PRICING_APP` with `BEARER_TOKEN`. There is no pricing service in this
project, so the code in this section is illustrative and wasn't run. The configuration format and
the `OUTBOUND_PRICING_APP__TOKEN` secret name were checked against the settings loader.

**1. Configuration.** Add an entry to `SECURITY_OUTBOUND_SERVICES` in `mycaller-app/.env` and its
secret under the `EnvSecretStore` naming scheme, `OUTBOUND_<CREDENTIAL_REF>__<KEY>`:

```bash
SECURITY_OUTBOUND_SERVICES='{
  "CALLED_APP": {...},
  "ANOTHER_CALLED_APP": {...},
  "PRICING_APP": {"service_id": "PRICING_APP", "base_url": "https://pricing.internal",
                  "auth_type": "BEARER_TOKEN", "credential_ref": "pricing-app"}
}'
OUTBOUND_PRICING_APP__TOKEN=<token from the pricing team / secrets manager>
```

`https` is required. `allow_insecure_http: true` is accepted only for `localhost`/`127.0.0.1`
during local development. Because `.env` is generated, also add the service to
`scripts/generate_credentials.py` so it survives regeneration, and add placeholders to
`.env.example`.

**2. Typed client.** Create `clients/pricing_app_client.py`, following
`clients/called_app_client.py`: a `SERVICE_ID = "PRICING_APP"` constant, a constructor that
checks `client.service_id`, and methods that call `self._client.get(...)` and validate the
response with a Pydantic `TypeAdapter`.

**3. Wiring in `main.py`:**
- If the app can't work without the service, add it to `REQUIRED_SERVICES` so a missing or wrong
  `auth_type` stops startup:
  ```python
  REQUIRED_SERVICES = {..., PricingAppClient.SERVICE_ID: AuthType.BEARER_TOKEN}
  ```
- Build the client in the lifespan:
  ```python
  app.state.pricing_app = PricingAppClient(security.client_for(PricingAppClient.SERVICE_ID))
  ```
- Expose it through a dependency in `api/dependencies.py`, then use it from a service method
  protected with `@pre_authorize(...)` and a route with `Depends(require_authority(...))`.

**4. Tests.** Add the service to `outbound_settings()` and its secret to `SECRETS` in
`tests/conftest.py`. Then extend `tests/test_outbound_integration.py` so it checks that the new
service gets only its own credential and the others never get it, following
`assert_called_app_credentials`.

## Test matrix for any new interceptor

| Case | Expected |
|---|---|
| Request to a service with the new `auth_type` | its credential header is present and correct |
| Requests to every other service | the new credential is absent |
| Its secret is missing | startup fails, and the error names the variable, never the value |
| Caller passes the credential header | `OutboundSecurityException`, nothing sent |
| A second interceptor for the same `AuthType` | startup fails ("Ambiguous") |
| Downstream returns 401 | a generic 502 to mycaller's client (plus one refresh-and-retry if `on_unauthorized()` is implemented) |
| The credential never appears in logs or error messages | `caplog` assertion, with a positive control |
| General interceptor | header present on the selected services, and it never touches credential headers |

## Matching the other side

A new outbound credential only works if the downstream accepts it. For called-app,
[adding an authentication provider](../../called-app/docs/adding-an-authentication-provider.md)
shows how to accept a new mechanism. Some common pairs:

| mycaller-app sends (`AuthType`) | Downstream must accept |
|---|---|
| `API_KEY` | `ApiKeyAuthenticationProvider` (called-app today) |
| `APP_CREDENTIALS` | `AppCredentialsAuthenticationProvider` (another-called-app today) |
| `BEARER_TOKEN` (static) or `OAUTH2_CLIENT_CREDENTIALS` | a bearer provider. For JWTs from an identity provider, use `JwtAuthenticationProvider` (the worked example in the called-app guide) |
