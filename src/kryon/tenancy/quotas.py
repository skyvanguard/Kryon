"""Resource quota enforcement for tenants."""

from __future__ import annotations

import logging

from kryon.tenancy.models import TIER_LIMITS

logger = logging.getLogger(__name__)


class ResourceQuotaEnforcer:
    """Enforces resource quotas per tenant."""

    def check_quota(self, tenant_id: str, resource: str, amount: int = 1) -> tuple[bool, str | None]:
        """Check if a tenant can consume a resource. Returns (allowed, reason_if_denied)."""
        from kryon.server.deps import get_store

        store = get_store()
        quotas = store.get_tenant_quotas(tenant_id)

        for q in quotas:
            if q["resource"] == resource:
                remaining = q["max_value"] - q["current_value"]
                if amount > remaining:
                    return (
                        False,
                        f"Quota exceeded for {resource}: {q['current_value']}/{q['max_value']} (need {amount})",
                    )
                return True, None

        # No quota defined — check tier defaults
        tenant = store.get_tenant(tenant_id)
        if tenant:
            tier = tenant.get("tier", "free")
            limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
            if resource in limits:
                logger.debug("Using tier default quota for %s/%s: %d", tenant_id, resource, limits[resource])
                return True, None

        # No quota restriction found — allow
        return True, None

    def consume_quota(self, tenant_id: str, resource: str, amount: int = 1) -> bool:
        """Consume a resource quota. Returns True if successful."""
        allowed, reason = self.check_quota(tenant_id, resource, amount)
        if not allowed:
            logger.warning("Quota denied: %s", reason)
            return False

        from kryon.server.deps import get_store

        return get_store().increment_quota_usage(tenant_id, resource, amount)

    def reset_monthly_quotas(self) -> None:
        """Reset monthly usage counters for all tenants."""
        from kryon.server.deps import get_store

        store = get_store()
        tenants = store.list_tenants()
        for tenant in tenants:
            for resource in ("scans", "users"):
                store.reset_quota_usage(tenant["id"], resource)
        logger.info("Reset monthly quotas for %d tenants", len(tenants))
