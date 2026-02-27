"""Tenant and quota models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class Tenant(BaseModel):
    """A tenant (organization) in the multi-tenant system."""

    id: str
    name: str
    slug: str
    tier: str = "free"  # 'free' | 'standard' | 'enterprise'
    is_active: bool = True
    config_json: dict[str, Any] = {}
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str | None = None


class TenantQuota(BaseModel):
    """Resource quota for a tenant."""

    id: str
    tenant_id: str
    resource: str  # 'scans' | 'users' | 'storage_mb'
    max_value: int
    current_value: int = 0
    reset_at: str | None = None


# Default quotas per tier
TIER_LIMITS: dict[str, dict[str, int]] = {
    "free": {"scans": 10, "users": 3, "storage_mb": 100},
    "standard": {"scans": 100, "users": 10, "storage_mb": 1024},
    "enterprise": {"scans": 999999, "users": 999999, "storage_mb": 10240},
}
