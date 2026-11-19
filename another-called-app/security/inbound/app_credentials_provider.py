"""Application ID + secret key authentication (`X-Application-Id` / `X-Secret-Key`).

New provider built per inbound-security.md §5.6. It combines the reference API key
provider's storage scheme (peppered HMAC-SHA256, `hmac.compare_digest`) with the Basic
provider's defence against account enumeration (a dummy hash is compared when the
application ID is unknown, so response timing does not reveal valid IDs).
"""

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass, field
from typing import Protocol

from starlette.requests import HTTPConnection

from security.exceptions import AuthenticationException
from security.inbound.authentication_provider import AuthenticationProvider
from security.inbound.principal import SecurityPrincipal

logger = logging.getLogger(__name__)

# Upper bound on presented values; longer input is rejected before hashing.
_MAX_CREDENTIAL_LENGTH = 512


def hash_secret_key(application_id: str, secret_key: str, pepper: bytes) -> str:
    """Keyed hash for storage: HMAC-SHA256(pepper, application_id + NUL + secret_key).

    Secret keys are high-entropy random values, so a fast HMAC is appropriate (unlike
    passwords). Binding the application ID into the MAC means a hash copied from one
    application's record onto another's never verifies. NUL cannot occur in an HTTP header
    value or in a configured application ID, so the encoding is unambiguous. The pepper lives
    in a secrets manager."""
    return hmac.new(pepper, f"{application_id}\0{secret_key}".encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class AppCredentialRecord:
    application_id: str  # non-secret identifier, safe to log
    secret_hash: str
    subject: str
    authorities: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)
    tenant_id: str | None = None
    enabled: bool = True


class AppCredentialStore(Protocol):
    async def find_by_application_id(self, application_id: str) -> AppCredentialRecord | None: ...


class InMemoryAppCredentialStore:
    def __init__(self, records: list[AppCredentialRecord]) -> None:
        ids = [r.application_id for r in records]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate application IDs in credential store")
        self._by_id = {r.application_id: r for r in records}

    async def find_by_application_id(self, application_id: str) -> AppCredentialRecord | None:
        return self._by_id.get(application_id)


class AppCredentialsAuthenticationProvider(AuthenticationProvider):
    name = "APP_CREDENTIALS"
    scheme = "AppCredentials"

    def __init__(
        self,
        store: AppCredentialStore,
        pepper: bytes,
        *,
        application_id_header: str = "X-Application-Id",
        secret_key_header: str = "X-Secret-Key",  # noqa: S107 - header name, not a secret
    ) -> None:
        if len(pepper) < 32:
            raise ValueError("App credentials pepper must be at least 32 bytes")
        self._store = store
        self._pepper = pepper
        self._id_header = application_id_header
        self._secret_header = secret_key_header
        # Compared when the application ID is unknown so timing does not reveal valid IDs.
        self._dummy_hash = hash_secret_key("unknown", os.urandom(32).hex(), pepper)

    def supports(self, connection: HTTPConnection) -> bool:
        # Inspects both headers and claims the request if EITHER is present. A request with
        # only one of them is then rejected by authenticate() (401) instead of degrading to
        # anonymous, which would let partial credentials through on public paths.
        headers = connection.headers
        return self._id_header in headers or self._secret_header in headers

    async def authenticate(self, connection: HTTPConnection) -> SecurityPrincipal:
        application_id = connection.headers.get(self._id_header, "").strip()
        secret_key = connection.headers.get(self._secret_header, "").strip()
        if (
            not application_id
            or not secret_key
            or len(application_id) > _MAX_CREDENTIAL_LENGTH
            or len(secret_key) > _MAX_CREDENTIAL_LENGTH
        ):
            reason = "partial_headers" if bool(application_id) != bool(secret_key) else "invalid"
            logger.info("App credentials authentication failed", extra={"reason": reason})
            raise self._failure(reason)

        presented_hash = hash_secret_key(application_id, secret_key, self._pepper)
        record = await self._store.find_by_application_id(application_id)
        # Always run the constant-time comparison, against the dummy hash for unknown IDs.
        expected_hash = record.secret_hash if record else self._dummy_hash
        valid = hmac.compare_digest(expected_hash, presented_hash)
        if record is None or not valid or not record.enabled:
            # Never log the presented ID for failures: it may be a mistyped secret.
            logger.info("App credentials authentication failed", extra={"reason": "invalid"})
            raise self._failure("invalid")
        return SecurityPrincipal(
            subject=record.subject,
            tenant_id=record.tenant_id,
            authorities=record.authorities,
            roles=record.roles,
            claims={"application_id": record.application_id},
            authentication_type=self.name,
        )

    def _failure(self, reason: str) -> AuthenticationException:
        return AuthenticationException("Invalid application credentials", scheme=self.scheme, reason=reason)
