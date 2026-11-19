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
