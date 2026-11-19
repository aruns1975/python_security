from typing import Any

import httpx

from security.outbound.secure_http_client import SecureHttpClient


class ServiceClient:
    """Client bound to one registered service, so callers cannot pick the wrong credentials."""

    def __init__(self, secure_client: SecureHttpClient, service_id: str) -> None:
        self._client = secure_client
        self.service_id = service_id

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return await self._client.request(self.service_id, method, path, **kwargs)

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", path, **kwargs)

    async def put(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", path, **kwargs)

    async def patch(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PATCH", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", path, **kwargs)
