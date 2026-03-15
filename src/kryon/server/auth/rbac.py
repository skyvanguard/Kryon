"""Role-Based Access Control for KRYON API."""

from __future__ import annotations

import os

from fastapi import Depends, HTTPException

from kryon.server.auth.deps import get_current_user
from kryon.server.auth.models import User

PERMISSIONS: dict[str, set[str]] = {
    "admin": {"*"},
    "analyst": {
        "runs:read",
        "runs:write",
        "scans:read",
        "scans:write",
        "engagements:read",
        "engagements:write",
        "clients:read",
        "reports:read",
        "reports:write",
        "knowledge:read",
        "knowledge:write",
        "evaluations:read",
        "scope:read",
        "scope:write",
        "integrations:read",
        "integrations:write",
    },
    "viewer": {
        "runs:read",
        "scans:read",
        "engagements:read",
        "clients:read",
        "reports:read",
        "knowledge:read",
        "evaluations:read",
        "scope:read",
    },
}


def _has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    role_perms = PERMISSIONS.get(role, set())
    if "*" in role_perms:
        return True
    return permission in role_perms


def require_permission(permission: str):
    """FastAPI dependency that checks the user has a specific permission.

    When JWT auth is not configured (API key only mode), admin-level
    permissions are blocked to prevent privilege escalation.
    """

    async def _check(user: User | None = Depends(get_current_user)):
        if user is None:
            # No JWT auth — block admin operations unless explicitly opted out
            if permission.startswith("admin:"):
                if os.getenv("KRYON_ALLOW_UNAUTHENTICATED", "").lower() not in ("true", "1", "yes"):
                    raise HTTPException(
                        status_code=403,
                        detail="Admin operations require JWT authentication with admin role",
                    )
            return None
        if not _has_permission(user.role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: {permission} required",
            )
        return user

    return _check
