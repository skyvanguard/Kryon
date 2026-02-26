"""Audit log API endpoints — admin only."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from kryon.server.auth import require_api_key
from kryon.server.auth.rbac import require_permission

router = APIRouter(tags=["audit"], dependencies=[Depends(require_api_key)])


@router.get("/audit")
async def get_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    user_id: str | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    _user=Depends(require_permission("admin:read")),
) -> list[dict]:
    """Get audit log entries. Admin only."""
    from kryon.server.routes.clients import _get_store

    store = _get_store()
    return store.get_audit_logs(
        limit=limit,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
    )
