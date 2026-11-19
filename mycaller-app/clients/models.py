"""Pydantic models for downstream responses.

Downstream services are untrusted input (outbound-security.md §8): every response is
validated against these models before business code sees it. Unknown fields are ignored so
additive downstream changes do not break the caller; missing or mistyped fields are rejected.
"""

from pydantic import BaseModel, ConfigDict, Field


class Order(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    id: str = Field(min_length=1, max_length=64)
    customer: str = Field(max_length=256)
    status: str = Field(max_length=32)
    total: float = Field(ge=0)


class InventoryItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    sku: str = Field(min_length=1, max_length=64)
    name: str = Field(max_length=256)
    quantity: int = Field(ge=0)
    warehouse: str = Field(max_length=64)
