"""Multi-tenancy support for KRYON — tenant resolution, isolation, and quotas."""

from __future__ import annotations

import contextvars
from typing import Any

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
