from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from main import create_app
from security.configuration import ApiKeyEntry, InboundSettings
from security.inbound.api_key_provider import hash_api_key

# Test-only values, generated for the suite; never used outside tests.
PEPPER = "test-pepper-" + "p" * 32
READER_KEY = "test-reader-key-0123456789abcdef"
NO_AUTHORITY_KEY = "test-noauth-key-0123456789abcdef"
DISABLED_KEY = "test-disabled-key-0123456789abcdef"


def _entry(key_id: str, key: str, authorities: set[str], enabled: bool = True) -> ApiKeyEntry:
    return ApiKeyEntry(
        key_id=key_id,
        key_hash=hash_api_key(key, PEPPER.encode()),
        subject=f"svc:{key_id}",
        authorities=frozenset(authorities),
        enabled=enabled,
    )


@pytest.fixture
def settings() -> InboundSettings:
    return InboundSettings(
        api_key_pepper=SecretStr(PEPPER),
        api_keys=(
            _entry("reader", READER_KEY, {"ORDER_READ"}),
            _entry("no-authority", NO_AUTHORITY_KEY, set()),
            _entry("disabled", DISABLED_KEY, {"ORDER_READ"}, enabled=False),
        ),
    )


@pytest.fixture
def app(settings: InboundSettings) -> FastAPI:
    return create_app(settings)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test"
    ) as c:
        yield c
