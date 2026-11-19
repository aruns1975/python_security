import contextvars

from security.outbound.interceptors.base import RequestInterceptor
from security.outbound.request_context import RequestContext

correlation_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("correlation_id", default=None)


class CorrelationIdInterceptor(RequestInterceptor):
    order = -100

    def __init__(self, header_name: str = "X-Correlation-ID") -> None:
        self._header = header_name

    async def intercept(self, context: RequestContext) -> None:
        correlation_id = correlation_id_var.get()
        if correlation_id:
            context.request.headers[self._header] = correlation_id
