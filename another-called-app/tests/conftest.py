from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from main import create_app
from security.configuration import AppCredentialEntry, InboundSettings
from security.inbound.app_credentials_provider import hash_secret_key

# Test-only values, generated for the suite; never used outside tests.
PEPPER = "test-pepper-" + "q" * 32
APP_ID = "test-reader-app"
SECRET = "test-reader-secret-0123456789abcdef"
NO_AUTHORITY_APP_ID = "test-noauth-app"
NO_AUTHORITY_SECRET = "test-noauth-secret-0123456789abcdef"
DISABLED_APP_ID = "test-disabled-app"
DISABLED_SECRET = "test-disabled-secret-0123456789abcdef"


def creds(application_id: str = APP_ID, secret_key: str = SECRET) -> dict[str, str]:
    return {"X-Application-Id": application_id, "X-Secret-Key": secret_key}


def _entry(application_id: str, secret: str, authorities: set[str], enabled: bool = True) -> AppCredentialEntry:
    return AppCredentialEntry(
        application_id=application_id,
        secret_hash=hash_secret_key(application_id, secret, PEPPER.encode()),
        subject=f"svc:{application_id}",
        authorities=frozenset(authorities),
        enabled=enabled,
    )


@pytest.fixture
def settings() -> InboundSettings:
    return InboundSettings(
        app_credentials_pepper=SecretStr(PEPPER),
        app_credentials=(
            _entry(APP_ID, SECRET, {"INVENTORY_READ"}),
            _entry(NO_AUTHORITY_APP_ID, NO_AUTHORITY_SECRET, set()),
            _entry(DISABLED_APP_ID, DISABLED_SECRET, {"INVENTORY_READ"}, enabled=False),
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
