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
