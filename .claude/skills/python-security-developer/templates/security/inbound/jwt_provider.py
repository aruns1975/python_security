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
