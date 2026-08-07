"""Usage metering — track and limit resource consumption."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Resource limits per tier
TIER_LIMITS = {
    "free": {"scans": 10, "agents": 3, "findings": 100, "engagements": 1},
    "standard": {"scans": 100, "agents": 10, "findings": 5000, "engagements": 10},
    "enterprise": {"scans": -1, "agents": -1, "findings": -1, "engagements": -1},  # -1 = unlimited
}


def record_usage(store, tenant_id: str, resource: str, amount: int = 1) -> None:
    """Record resource usage."""
    now = datetime.now(timezone.utc).isoformat()
    store.record_usage(
        usage_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        resource=resource,
        amount=amount,
        recorded_at=now,
    )


def get_usage_summary(store, tenant_id: str, period: str = "") -> dict:
    """Get usage summary for a tenant."""
    return store.get_usage_summary(tenant_id=tenant_id, since=period)


def check_limit(store, tenant_id: str, resource: str, tier: str = "free") -> tuple[bool, int]:
    """Check if resource usage is within limits.

    Returns (allowed, remaining). remaining=-1 means unlimited.
    """
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    max_val = limits.get(resource, 0)

    if max_val == -1:
        return True, -1

    # Sum current usage
    summary = store.get_usage_summary(tenant_id=tenant_id)
    current = 0
    for item in summary:
        if item.get("resource") == resource:
            current = item.get("total", 0)
            break

    remaining = max(max_val - current, 0)
    return remaining > 0, remaining
