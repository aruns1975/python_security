from dataclasses import dataclass, field
from typing import Any

import httpx

from security.outbound.service_registry import ServiceConfig


@dataclass
class RequestContext:
    service: ServiceConfig
    request: httpx.Request
    attempt: int = 1
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def service_id(self) -> str:
        return self.service.service_id
