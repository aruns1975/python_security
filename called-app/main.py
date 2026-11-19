"""Called application (port 48081): downstream service secured by API key (`X-API-Key`).

Run: uvicorn --factory main:create_app --host 127.0.0.1 --port 48081
"""

from fastapi import FastAPI

from api.routes import orders
from security.configuration import InboundSettings, build_providers, configure_inbound_security


def create_app(settings: InboundSettings | None = None) -> FastAPI:
    """Application factory. Reads settings from the environment when none are given;
    missing security configuration raises here, so the process never starts unprotected."""
    settings = settings or InboundSettings()  # values come from the environment
    app = FastAPI(title="Called application")
    configure_inbound_security(app, build_providers(settings), settings.public_paths, challenge_scheme="ApiKey")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(orders.router)
    return app
