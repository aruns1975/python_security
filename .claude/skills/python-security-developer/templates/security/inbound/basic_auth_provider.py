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
