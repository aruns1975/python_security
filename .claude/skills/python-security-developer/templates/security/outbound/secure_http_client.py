import asyncio
import logging
import random
import time
from collections.abc import Mapping
from typing import Any

import httpx

from security.exceptions import OutboundSecurityException, OutboundServiceError
from security.outbound.interceptor_manager import InterceptorManager
from security.outbound.request_context import RequestContext
from security.outbound.service_registry import ServiceConfig, ServiceRegistry

logger = logging.getLogger(__name__)

_IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
_RETRYABLE_STATUS = frozenset({502, 503, 504})
_RESERVED_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "host"})


class SecureHttpClient:
    """The only way application code talks to registered downstream services."""

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        registry: ServiceRegistry,
        interceptors: InterceptorManager,
        *,
        backoff_base_seconds: float = 0.2,
    ) -> None:
        self._http = http_client
        self._registry = registry
        self._interceptors = interceptors
        self._backoff = backoff_base_seconds
        interceptors.validate(registry)

    async def request(
        self,
        service_id: str,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        json: Any = None,
        content: bytes | None = None,
        data: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        service = self._registry.get(service_id)
        method = method.upper()
        url = self._resolve_url(service, path)
        safe_headers = self._check_headers(service, headers)
        retries = service.max_retries if self._retryable(method, safe_headers) else 0

        attempt = 0
        unauthorized_retry_used = False
        while True:
            attempt += 1
            request = self._http.build_request(
                method, url, params=params, headers=safe_headers, json=json, content=content, data=data,
                timeout=service.timeout,
            )
            context = RequestContext(service=service, request=request, attempt=attempt)
            auth = await self._interceptors.execute(context)
            self._assert_destination(service, context.request.url)

            started = time.perf_counter()
            try:
                response = await self._http.send(context.request, follow_redirects=False)
            except httpx.TransportError as exc:
                if attempt <= retries:
                    await self._sleep(attempt)
                    continue
                logger.warning("Outbound request failed", extra=self._log_fields(service, method, path, None, started))
                raise OutboundServiceError(service_id, None, f"transport error ({type(exc).__name__})") from None

            logger.info("Outbound request completed", extra=self._log_fields(service, method, path, response.status_code, started))

            if response.status_code == 401 and not unauthorized_retry_used:
                unauthorized_retry_used = True
                if await auth.on_unauthorized(context, response):
                    await response.aclose()
                    continue
            if response.status_code in _RETRYABLE_STATUS and attempt <= retries:
                await response.aclose()
                await self._sleep(attempt)
                continue
            if not response.is_success:
                # Never put the URL (query may hold secrets) or body in the message.
                raise OutboundServiceError(service_id, response.status_code, f"{method} {path} returned {response.status_code}")
            return response

    @staticmethod
    def _resolve_url(service: ServiceConfig, path: str) -> httpx.URL:
        """Only relative paths under the registered base URL are allowed (SSRF / credential-leak guard)."""
        if (
            not path.startswith("/")
            or path.startswith("//")
            or "://" in path
            or "\\" in path
            or "?" in path
            or "#" in path
            or any(segment in ("..", ".") for segment in path.split("/"))
        ):
            raise OutboundSecurityException("Path must be a relative path under the service base URL; use params= for queries")
        base = httpx.URL(service.base_url)
        return base.copy_with(path=base.path.rstrip("/") + path)

    @staticmethod
    def _assert_destination(service: ServiceConfig, url: httpx.URL) -> None:
        if (url.scheme, url.host, url.port) != service.origin:
            raise OutboundSecurityException(f"Destination does not match registered origin for {service.service_id}")
        if url.scheme != "https" and not service.allow_insecure_http:
            raise OutboundSecurityException("Credentials may only be sent over https")

    @staticmethod
    def _check_headers(service: ServiceConfig, headers: Mapping[str, str] | None) -> dict[str, str]:
        if not headers:
            return {}
        reserved = _RESERVED_HEADERS | {service.api_key_header.lower()}
        clash = [name for name in headers if name.lower() in reserved]
        if clash:
            raise OutboundSecurityException(f"Caller may not set credential headers: {clash}")
        return dict(headers)

    @staticmethod
    def _retryable(method: str, headers: Mapping[str, str]) -> bool:
        # Non-idempotent calls retry only when the caller supplies an idempotency key.
        return method in _IDEMPOTENT or any(name.lower() == "idempotency-key" for name in headers)

    async def _sleep(self, attempt: int) -> None:
        await asyncio.sleep(self._backoff * (2 ** (attempt - 1)) * (0.5 + random.random()))  # noqa: S311 - jitter, not crypto

    @staticmethod
    def _log_fields(service: ServiceConfig, method: str, path: str, status: int | None, started: float) -> dict[str, Any]:
        return {
            "service_id": service.service_id,
            "auth_type": str(service.auth_type),
            "method": method,
            "path": path,  # path only; query strings and headers are never logged
            "status": status,
            "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        }
