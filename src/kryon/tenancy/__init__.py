"""Multi-tenancy support for KRYON — tenant resolution, isolation, and quotas."""

from __future__ import annotations

import contextvars
from typing import Any

from kryon.tenancy.scope import (
    ScopePolicy,
    TenantContext,
    is_target_in_scope,
    load_scope_policy,
    namespaced_engagement_id,
    namespaced_path,
)

# Context variable for current tenant
_current_tenant: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("current_tenant", default=None)


def get_tenant() -> dict[str, Any] | None:
    """Get the current tenant from context."""
    return _current_tenant.get()


def set_tenant(tenant: dict[str, Any] | None) -> contextvars.Token:
    """Set the current tenant in context."""
    return _current_tenant.set(tenant)


def get_tenant_id() -> str | None:
    """Get the current tenant ID."""
    tenant = get_tenant()
    return tenant["id"] if tenant else None


__all__ = [
    "get_tenant",
    "set_tenant",
    "get_tenant_id",
    # F146 scope primitives
    "ScopePolicy",
    "TenantContext",
    "is_target_in_scope",
    "load_scope_policy",
    "namespaced_engagement_id",
    "namespaced_path",
]
