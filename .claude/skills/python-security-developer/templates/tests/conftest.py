import time
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://idp.example.com/"
AUDIENCE = "orders-api"


@pytest.fixture(scope="session")
def rsa_keys() -> tuple[Any, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_pem


@pytest.fixture
def make_token(rsa_keys: tuple[Any, bytes]) -> Callable[..., str]:
    private_key, _ = rsa_keys

    def _make(sub: str = "user-1", *, scope: str = "ORDER_READ", roles: list[str] | None = None,
              exp_offset: int = 300, **overrides: Any) -> str:
        now = int(time.time())
        claims = {"sub": sub, "iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + exp_offset,
                  "scope": scope, "roles": roles or []}
        claims.update(overrides)
        return jwt.encode(claims, private_key, algorithm="RS256")

    return _make
