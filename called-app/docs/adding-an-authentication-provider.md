# Adding an authentication provider to called-app

called-app accepts one inbound mechanism today: an API key in `X-API-Key`. This guide shows how to
accept another one, for example JWT bearer tokens from an identity provider, without touching the
middleware or the endpoints.

The first section lists the steps for any provider. The second walks through a complete,
tested example that adds JWT bearer authentication next to the API key. The third covers writing
a provider from scratch for a custom scheme.

## How providers fit in

```text
request ─► SecurityMiddleware ─► AuthenticationManager
                                   ├─ ApiKeyAuthenticationProvider.supports()?   X-API-Key present
                                   └─ <YourProvider>.supports()?                 your credential present
                                        no provider matches   → anonymous (401 unless /health or docs)
                                        more than one matches → 401 "Ambiguous authentication"
                                        exactly one matches   → provider.authenticate() → SecurityPrincipal or 401
```

Endpoints don't change. They check **authorities** (`require_authority("ORDER_READ")`), not how the
caller authenticated, so a new provider only needs to give its callers the right authorities.

## Steps for any new provider

| # | Step | File |
|---|---|---|
| 1 | Add the provider class (copy one from the skill's templates, or write one, as in section 3) | `security/inbound/<name>_provider.py` |
| 2 | Add any new library to the dependencies (`uv add <package>`) | `pyproject.toml` |
| 3 | Add its settings to `InboundSettings`: off by default, and a validator that refuses to start when it's enabled but incomplete | `security/configuration.py` |
| 4 | Append the provider in `build_providers()` when it's enabled | `security/configuration.py` |
| 5 | Declare its header for Swagger with a **unique** `scheme_name` | `security/inbound/dependencies.py` |
| 6 | Document the new environment variables (names and placeholders only) | `.env.example`, `README.md` |
| 7 | Add tests (matrix below) and update the existing OpenAPI scheme test | `tests/` |
| 8 | Run `uv run pytest -q`, `uv run ruff check .` and `uv run mypy .`, then `./app.sh restart` | |
| 9 | Make the callers send the new credential (for mycaller-app, see [adding an outbound interceptor](../../mycaller-app/docs/adding-an-outbound-interceptor.md)) | caller |

Rules that keep the app secure:
- **`supports()` only checks that the credential is present.** All validation goes in `authenticate()`.
- **`authenticate()` returns a `SecurityPrincipal`, or raises `AuthenticationException`.** The message must be generic, `scheme` must be right for `WWW-Authenticate`, and `reason` must be non-secret (`invalid`, `missing`, ...).
- **Give the provider a unique `name`.** It is logged as the authentication type, and `AuthenticationManager` refuses to start with duplicate names.
- **Never log the credential itself.** Log only the failure type.
- **Don't change the middleware, `AuthenticationManager` or the routes.** If you think you need to, the provider is doing too much.
- **Add no public paths.** The allow-list in `security/configuration.py` is deliberately fixed.

## Worked example: JWT bearer tokens next to the API key

The result: callers can send either `X-API-Key: <key>` or `Authorization: Bearer <jwt>`, but not
both. A JWT gets the authorities in its `scope` claim, so a token with `scope: "ORDER_READ"` can
read orders.

### 1. Copy the provider

The skill ships a tested JWT provider. It checks the signature, `exp`, `iat`, `iss` and `aud`
against an explicit algorithm list, refuses the `none` algorithm, and rejects settings that mix
HMAC and RSA algorithms.

```bash
cp ../.claude/skills/python-security-developer/templates/security/inbound/jwt_provider.py security/inbound/
uv add "pyjwt[crypto]>=2.8"
```

### 2. Settings: `security/configuration.py`

Import the provider and `model_validator`:

```python
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
...
from security.inbound.jwt_provider import JwtAuthenticationProvider, JwtSettings
```

Add these fields to `InboundSettings`, after `public_paths`:

```python
    # Second provider: JWT bearer tokens. Off unless explicitly enabled; when enabled, issuer,
    # audience and exactly one key source are required (JwtSettings enforces the key source).
    jwt_enabled: bool = False
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    jwt_jwks_url: str | None = None
    jwt_public_key_pem: str | None = None
    jwt_algorithms: tuple[str, ...] = ("RS256",)
```

Then add this validator to `InboundSettings`, after the existing `public_paths` validator:

```python
    @model_validator(mode="after")
    def _jwt_settings_complete(self) -> "InboundSettings":
        if self.jwt_enabled and not (self.jwt_issuer and self.jwt_audience):
            raise ValueError("jwt_issuer and jwt_audience are required when jwt_enabled is true")
        return self
```

### 3. Register it: `build_providers()` in `security/configuration.py`

```python
def build_providers(settings: InboundSettings) -> list[AuthenticationProvider]:
    """API key always; JWT bearer when enabled. A request may carry only one of them."""
    store = InMemoryApiKeyStore([entry.to_record() for entry in settings.api_keys])
    # Provider enforces a >= 32-byte pepper.
    pepper = settings.api_key_pepper.get_secret_value().encode()
    providers: list[AuthenticationProvider] = [
        ApiKeyAuthenticationProvider(store, pepper, header_name=settings.api_key_header)
    ]
    if settings.jwt_enabled:
        assert settings.jwt_issuer and settings.jwt_audience  # checked by the model validator
        providers.append(
            JwtAuthenticationProvider(
                JwtSettings(
                    issuer=settings.jwt_issuer,
                    audience=settings.jwt_audience,
                    algorithms=settings.jwt_algorithms,
                    jwks_url=settings.jwt_jwks_url,
                    static_key=settings.jwt_public_key_pem,
                )
            )
        )
    return providers
```

`main.py` doesn't change: it already passes `build_providers(settings)` to the middleware.

### 4. Show it in Swagger: `security/inbound/dependencies.py`

```python
from fastapi.security import APIKeyHeader, HTTPBearer

_api_key_scheme = APIKeyHeader(name="X-API-Key", scheme_name="ApiKey", auto_error=False)
_bearer_scheme = HTTPBearer(scheme_name="Bearer", bearerFormat="JWT", auto_error=False)


async def get_current_principal(
    _api_key: Annotated[object, Depends(_api_key_scheme)] = None,
    _bearer: Annotated[object, Depends(_bearer_scheme)] = None,
) -> SecurityPrincipal:
    return SecurityContextHolder.require_principal()
```

These declarations only document the schemes. The middleware still does all authentication.
Always set `scheme_name`: two schemes of the same class share a default name, and the second
silently replaces the first in the spec.

### 5. Environment variables

Add these to `.env.example`, and to the environment table in `README.md`:

```bash
# Optional second provider: JWT bearer tokens (off by default).
# SECURITY_INBOUND_JWT_ENABLED=true
# SECURITY_INBOUND_JWT_ISSUER=https://idp.example.com/
# SECURITY_INBOUND_JWT_AUDIENCE=called-app
# Exactly one key source:
# SECURITY_INBOUND_JWT_JWKS_URL=https://idp.example.com/.well-known/jwks.json
# SECURITY_INBOUND_JWT_PUBLIC_KEY_PEM="-----BEGIN PUBLIC KEY-----..."
# SECURITY_INBOUND_JWT_ALGORITHMS='["RS256"]'
```

Startup fails if JWT is enabled without an issuer and audience, without a key source, with both
key sources, or with a JWKS URL that isn't https.

The identity provider must put the needed authorities in the token's `scope` claim
(space-separated, for example `"ORDER_READ"`). If yours uses a different claim (Auth0 uses
`permissions`, Keycloak `realm_access.roles`), set `authorities_claim` in `JwtSettings`.

### 6. Tests

Change the existing OpenAPI test in `tests/test_inbound.py` to expect both schemes:

```python
    assert spec["components"]["securitySchemes"] == {
        "ApiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        "Bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
    }
```

Add `tests/test_jwt_provider.py`. The tests generate an RSA key and sign their own tokens, so no
identity provider is needed:

```python
"""JWT bearer provider added next to the API key provider."""

import time
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from main import create_app
from security.configuration import InboundSettings
from tests.conftest import READER_KEY

ISSUER = "https://idp.example.com/"
AUDIENCE = "called-app"
API = "/api/v1/orders"


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def make_token(rsa_key: rsa.RSAPrivateKey) -> Callable[..., str]:
    def _make(scope: str = "ORDER_READ", exp_offset: int = 300, **overrides: Any) -> str:
        now = int(time.time())
        claims = {"sub": "svc:reporting", "iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + exp_offset, "scope": scope}
        claims.update(overrides)
        return jwt.encode(claims, rsa_key, algorithm="RS256")

    return _make


@pytest.fixture
async def jwt_client(settings: InboundSettings, rsa_key: rsa.RSAPrivateKey) -> AsyncIterator[httpx.AsyncClient]:
    public_pem = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    jwt_settings = settings.model_copy(
        update={"jwt_enabled": True, "jwt_issuer": ISSUER, "jwt_audience": AUDIENCE, "jwt_public_key_pem": public_pem}
    )
    app = create_app(jwt_settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_valid_jwt_with_authority(jwt_client: httpx.AsyncClient, make_token: Callable[..., str]) -> None:
    assert (await jwt_client.get(API, headers=bearer(make_token()))).status_code == 200


async def test_api_key_still_works(jwt_client: httpx.AsyncClient) -> None:
    assert (await jwt_client.get(API, headers={"X-API-Key": READER_KEY})).status_code == 200


@pytest.mark.parametrize("overrides", [{"exp_offset": -120}, {"aud": "other-api"}, {"iss": "https://evil.example.com/"}])
async def test_invalid_jwt_401(jwt_client: httpx.AsyncClient, make_token: Callable[..., str], overrides: dict[str, Any]) -> None:
    r = await jwt_client.get(API, headers=bearer(make_token(**overrides)))
    assert r.status_code == 401 and r.json()["detail"] == "Invalid or expired token"


async def test_jwt_without_authority_403(jwt_client: httpx.AsyncClient, make_token: Callable[..., str]) -> None:
    assert (await jwt_client.get(API, headers=bearer(make_token(scope="OTHER")))).status_code == 403


async def test_both_credentials_rejected_as_ambiguous(jwt_client: httpx.AsyncClient, make_token: Callable[..., str]) -> None:
    r = await jwt_client.get(API, headers={**bearer(make_token()), "X-API-Key": READER_KEY})
    assert r.status_code == 401 and "Ambiguous" in r.json()["detail"]


async def test_bearer_ignored_when_jwt_disabled(client: httpx.AsyncClient, make_token: Callable[..., str]) -> None:
    # JWT off (default): a bearer token is just "no credentials" -> 401.
    assert (await client.get(API, headers=bearer(make_token()))).status_code == 401


async def test_openapi_lists_both_schemes(jwt_client: httpx.AsyncClient) -> None:
    spec = (await jwt_client.get("/openapi.json")).json()
    assert set(spec["components"]["securitySchemes"]) == {"ApiKey", "Bearer"}


def test_enabled_jwt_requires_issuer_and_audience(settings: InboundSettings) -> None:
    with pytest.raises(ValidationError, match="jwt_issuer and jwt_audience"):
        InboundSettings.model_validate({**settings.model_dump(), "api_key_pepper": "x" * 40, "jwt_enabled": True})
```

This example was run against a copy of called-app: 48 tests passed, and ruff and mypy were clean.

### 7. Restart and try it

```bash
./app.sh restart
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:48081/api/v1/orders     # 200 with ORDER_READ in scope
```

The challenge header on an anonymous request stays `WWW-Authenticate: ApiKey`, the value
`main.py` passes as `challenge_scheme`. Invalid tokens get `WWW-Authenticate: Bearer` from the JWT
provider.

## Writing a provider for a custom scheme

If no template fits (an HMAC-signed request, a partner's proprietary header and so on), use
`another-called-app/security/inbound/app_credentials_provider.py` as the model. It is a complete
custom provider. The skeleton:

```python
import hmac
import logging

from starlette.requests import HTTPConnection

from security.exceptions import AuthenticationException
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.principal import SecurityPrincipal

logger = logging.getLogger(__name__)


class PartnerTokenAuthenticationProvider(AuthenticationProvider):
    name = "PARTNER_TOKEN"  # unique; logged as the authentication type

    def supports(self, connection: HTTPConnection) -> bool:
        # Presence only. If the scheme uses several headers, claim the request when ANY of them
        # is present, so a partial credential gets a 401 instead of passing as anonymous.
        return "X-Partner-Token" in connection.headers

    async def authenticate(self, connection: HTTPConnection) -> SecurityPrincipal:
        presented = connection.headers.get("X-Partner-Token", "")
        record = await self._store.find(...)            # look up by a non-secret id or a hash
        if record is None or not hmac.compare_digest(record.expected, ...):
            logger.info("Partner token authentication failed")      # never log the token
            raise AuthenticationException("Invalid credentials", scheme="PartnerToken", reason="invalid")
        return SecurityPrincipal(
            subject=record.subject,
            authentication_type=self.name,
            authorities=record.authorities,
        )
```

Checklist for custom providers:
- **Store only hashes.** Use a peppered HMAC (`hash_api_key` in `api_key_provider.py`) for random keys, or argon2id/scrypt for passwords.
- **Compare with `hmac.compare_digest`.** For unknown IDs, compare against a dummy hash so response timing doesn't reveal which IDs exist.
- **Cap the length** of presented values before hashing.
- **Run CPU-heavy verification off the event loop** with `await asyncio.to_thread(...)`.

## Test matrix for any new provider

| Case | Expected |
|---|---|
| Valid credential with the required authority | 200 |
| Valid credential without the authority | 403 |
| Invalid, expired or wrong-audience credential | 401, generic message, correct `WWW-Authenticate` |
| Credential missing | 401 (`/health` and the docs still 200) |
| Partial credential (multi-header schemes) | 401, including on `/health` |
| New credential plus an API key in the same request | 401 "Ambiguous authentication" |
| Existing API-key callers | unchanged (200) |
| Provider disabled (default) | its credential is ignored, so 401 |
| Enabled but incomplete settings | startup fails |
| The credential never appears in logs | `caplog` assertion, with a positive control |
