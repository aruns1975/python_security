"""Response validation shared by the typed downstream clients."""

from typing import TypeVar

import httpx
from pydantic import TypeAdapter, ValidationError

from security.exceptions import OutboundServiceError

T = TypeVar("T")


def parse_response(service_id: str, response: httpx.Response, adapter: TypeAdapter[T]) -> T:
    """Validate a downstream body. A malformed body is reported like any other downstream
    failure (status only, no body content in the message, which may echo secrets)."""
    try:
        return adapter.validate_json(response.content)
    except ValidationError:
        raise OutboundServiceError(service_id, response.status_code, "invalid response body") from None
