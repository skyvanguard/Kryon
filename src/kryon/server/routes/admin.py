"""Admin API endpoints — backup, health, user management."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.auth.models import UserPublic
from kryon.server.auth.password import hash_password, validate_password_complexity
from kryon.server.auth.rbac import require_permission

router = APIRouter(tags=["admin"], dependencies=[Depends(require_api_key)])


def _get_store():
    from kryon.server.routes.clients import _get_store as get_store
    return get_store()


# -----------------------------------------------------------------------
# Backup
# -----------------------------------------------------------------------


@router.post("/admin/backup")
async def create_backup(_user=Depends(require_permission("admin:write"))):
    """Create a SQLite database backup. Admin only."""
    store = _get_store()
    backup_dir = Path.home() / ".kryon" / "backups"
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = backup_dir / f"kryon_backup_{ts}.db"
    store.backup(backup_path)
    return {"path": str(backup_path), "timestamp": ts}


# -----------------------------------------------------------------------
# Extended Health
# -----------------------------------------------------------------------


@router.get("/admin/health")
async def admin_health(_user=Depends(require_permission("admin:read"))):
    """Extended health check with system details. Admin only."""
    store = _get_store()
    conn = store._get_conn()

    # Schema version
    row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    schema_version = row["version"] if row else 0

    # User count
    user_count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]

    # DB file size
    db_path = store._db_path
    db_size = db_path.stat().st_size if db_path.exists() else 0

    # Table row counts
    tables = {}
    for table in ["clients", "scans", "findings", "engagements", "engagement_phases", "audit_log"]:
        try:
            count = conn.execute(f"SELECT COUNT(*) as c FROM {table}").fetchone()["c"]
            tables[table] = count
        except Exception:
            tables[table] = -1

    return {
        "status": "ok",
        "schema_version": schema_version,
        "user_count": user_count,
        "db_size_bytes": db_size,
        "db_path": str(db_path),
        "tables": tables,
    }


# -----------------------------------------------------------------------
# User Management
# -----------------------------------------------------------------------


class AdminCreateUser(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., min_length=1, max_length=200)
    password: str = Field(..., min_length=8, max_length=200)
    role: str = Field("analyst", pattern="^(admin|analyst|viewer)$")


class AdminUpdateUser(BaseModel):
    email: str | None = None
    role: str | None = Field(None, pattern="^(admin|analyst|viewer)$")
    is_active: bool | None = None


@router.get("/admin/users", response_model=list[UserPublic])
async def list_users(_user=Depends(require_permission("admin:read"))):
    """List all users. Admin only."""
    store = _get_store()
    users = store.list_users()
    return [UserPublic(**u.model_dump()) for u in users]


@router.post("/admin/users", response_model=UserPublic)
async def create_user(req: AdminCreateUser, _user=Depends(require_permission("admin:write"))):
    """Create a new user. Admin only."""
    from kryon.server.auth.models import User

    complexity_error = validate_password_complexity(req.password)
    if complexity_error:
        raise HTTPException(400, complexity_error)

    store = _get_store()

    # Check uniqueness
    if store.get_user_by_username(req.username):
        raise HTTPException(400, "Username already exists")

    user = User(
        username=req.username,
        email=req.email,
        password_hash=hash_password(req.password),
        role=req.role,
    )
    store.create_user(user)
    return UserPublic(**user.model_dump())


@router.put("/admin/users/{user_id}", response_model=UserPublic)
async def update_user(user_id: str, req: AdminUpdateUser, _user=Depends(require_permission("admin:write"))):
    """Update a user. Admin only."""
    store = _get_store()
    existing = store.get_user_by_id(user_id)
    if not existing:
        raise HTTPException(404, "User not found")

    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(400, "No fields to update")

    store.update_user(user_id, **updates)
    updated = store.get_user_by_id(user_id)
    return UserPublic(**updated.model_dump())


@router.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, _user=Depends(require_permission("admin:write"))):
    """Delete a user. Admin only."""
    store = _get_store()
    if not store.delete_user(user_id):
        raise HTTPException(404, "User not found")
    return {"deleted": True}
