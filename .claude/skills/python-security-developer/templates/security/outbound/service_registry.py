import ipaddress
from collections.abc import Mapping
from enum import StrEnum

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from security.exceptions import OutboundSecurityException


class AuthType(StrEnum):
    NONE = "NONE"
    API_KEY = "API_KEY"
    BASIC = "BASIC"
    OAUTH2_CLIENT_CREDENTIALS = "OAUTH2_CLIENT_CREDENTIALS"


class ServiceConfig(BaseModel):
    """Metadata for one downstream service. Holds secret *references*, never secrets."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service_id: str
    base_url: str
    auth_type: AuthType
    credential_ref: str | None = None
    api_key_header: str = "X-API-Key"
    token_url: str | None = None
    scopes: tuple[str, ...] = ()
    connect_timeout: float = Field(default=3.0, gt=0)
    read_timeout: float = Field(default=10.0, gt=0)
    max_retries: int = Field(default=2, ge=0, le=5)
    allow_insecure_http: bool = False  # local development only; loopback hosts only

    @model_validator(mode="after")
    def _validate(self) -> "ServiceConfig":
        url = httpx.URL(self.base_url)
        if url.scheme not in ("https", "http") or not url.host:
            raise ValueError(f"{self.service_id}: base_url must be an absolute http(s) URL")
        if url.scheme == "http" and not self.allow_insecure_http:
            raise ValueError(f"{self.service_id}: base_url must use https")
        if self.allow_insecure_http and not _is_loopback(url.host):
            raise ValueError(f"{self.service_id}: allow_insecure_http is only permitted for loopback hosts")
        if url.userinfo or url.query or url.fragment:
            raise ValueError(f"{self.service_id}: base_url must not contain credentials, query or fragment")
        if self.auth_type is not AuthType.NONE and not self.credential_ref:
            raise ValueError(f"{self.service_id}: credential_ref is required for {self.auth_type}")
        if self.auth_type is AuthType.OAUTH2_CLIENT_CREDENTIALS:
            if not self.token_url or httpx.URL(self.token_url).scheme != "https":
                raise ValueError(f"{self.service_id}: token_url must be an https URL")
        return self

    @property
    def origin(self) -> tuple[str, str, int | None]:
        url = httpx.URL(self.base_url)
        return url.scheme, url.host, url.port

    @property
    def timeout(self) -> httpx.Timeout:
        return httpx.Timeout(self.read_timeout, connect=self.connect_timeout)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ServiceRegistry:
    def __init__(self, services: Mapping[str, ServiceConfig]) -> None:
        for key, config in services.items():
            if key != config.service_id:
                raise ValueError(f"Registry key {key!r} does not match service_id {config.service_id!r}")
        self._services = dict(services)

    def get(self, service_id: str) -> ServiceConfig:
        try:
            return self._services[service_id]
        except KeyError:
            raise OutboundSecurityException(f"Unknown service: {service_id!r}") from None

    def all(self) -> list[ServiceConfig]:
        return list(self._services.values())
