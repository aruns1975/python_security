"""Another Called application (port 38081): downstream service secured by application
credentials (`X-Application-Id` + `X-Secret-Key`).

Run: uvicorn --factory main:create_app --host 127.0.0.1 --port 38081
"""

from fastapi import FastAPI

from api.routes import inventory
from security.configuration import InboundSettings, build_providers, configure_inbound_security
from security.inbound.app_credentials_provider import AppCredentialsAuthenticationProvider


def create_app(settings: InboundSettings | None = None) -> FastAPI:
    """Application factory. Reads settings from the environment when none are given;
    missing security configuration raises here, so the process never starts unprotected."""
    settings = settings or InboundSettings()  # values come from the environment
    app = FastAPI(title="Another Called application")
    configure_inbound_security(
        app,
        build_providers(settings),
        settings.public_paths,
        challenge_scheme=AppCredentialsAuthenticationProvider.scheme,
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(inventory.router)
    return app
