import os
import re
from typing import Protocol


class SecretStore(Protocol):
    """Resolves secret references (AWS Secrets Manager, Vault, K8s secrets, env...)."""

    async def get_secret(self, reference: str, key: str) -> str: ...


class EnvSecretStore:
    """Reads `<PREFIX><REFERENCE>__<KEY>` env vars, e.g. ref `service-b-basic-auth`, key
    `password` -> `OUTBOUND_SERVICE_B_BASIC_AUTH__PASSWORD`. Suitable when the platform
    injects secrets as env vars; otherwise implement SecretStore over your secrets manager."""

    def __init__(self, prefix: str = "OUTBOUND_") -> None:
        self._prefix = prefix

    async def get_secret(self, reference: str, key: str) -> str:
        name = f"{self._prefix}{_env_part(reference)}__{_env_part(key)}"
        value = os.environ.get(name)
        if not value:
            # Name the variable, never the value.
            raise LookupError(f"Secret not configured: {name}")
        return value


def _env_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", value).upper()
