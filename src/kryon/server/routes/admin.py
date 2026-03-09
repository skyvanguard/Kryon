"""Admin API endpoints — backup, health, user management."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.auth.models import UserPublic
from kryon.server.auth.password import hash_password, validate_password_complexity
from kryon.server.auth.rbac import require_permission
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["admin"], dependencies=[Depends(require_api_key)])


# -----------------------------------------------------------------------
# Backup
# -----------------------------------------------------------------------


_BACKUP_DIR = Path.home() / ".kryon" / "backups"

_EXPORTABLE_TABLES = {
    "clients",
    "scans",
    "findings",
    "assets",
    "engagements",
    "audit_log",
    "notification_log",
    "iocs",
}


@router.post("/admin/backup")
async def create_backup(_user=Depends(require_permission("admin:write"))):
    """Create a SQLite database backup. Admin only."""
    store = get_store()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = _BACKUP_DIR / f"kryon_backup_{ts}.db"
    store.backup(backup_path)
    logger.info("Database backup created: %s", backup_path)
    return {"path": str(backup_path), "timestamp": ts}


@router.get("/admin/backups")
async def list_backups(_user=Depends(require_permission("admin:read"))):
    """List all database backups with metadata."""
    if not _BACKUP_DIR.exists():
        return []
    backups = []
    for f in sorted(_BACKUP_DIR.glob("kryon_backup_*.db")):
        stat = f.stat()
        backups.append(
            {
                "filename": f.name,
                "size_bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            }
        )
    return backups


@router.delete("/admin/backups/{filename}")
async def delete_backup(filename: str, _user=Depends(require_permission("admin:write"))):
    """Delete a specific backup file."""
    # Path traversal protection
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    target = _BACKUP_DIR / filename
    if not target.exists() or not target.name.startswith("kryon_backup_"):
        raise not_found("Backup", filename)
    target.unlink()
    logger.info("Backup deleted: %s", filename)
    return {"deleted": True, "filename": filename}


class RotateRequest(BaseModel):
    keep: int = Field(10, ge=1, le=1000)


@router.post("/admin/backup/rotate")
async def rotate_backups(req: RotateRequest, _user=Depends(require_permission("admin:write"))):
    """Delete oldest backups, keeping only the most recent N."""
    if not _BACKUP_DIR.exists():
        return {"deleted_count": 0}
    files = sorted(_BACKUP_DIR.glob("kryon_backup_*.db"), key=lambda f: f.stat().st_mtime)
    to_delete = files[: max(0, len(files) - req.keep)]
    for f in to_delete:
        f.unlink()
    logger.info("Backup rotation: deleted %d, kept %d", len(to_delete), req.keep)
    return {"deleted_count": len(to_delete), "kept": req.keep}


@router.get("/admin/export/{table}")
async def export_table(
    table: str,
    client_id: str = Query("", description="Filter by client_id"),
    _user=Depends(require_permission("admin:read")),
):
    """Export a table as JSON. Only whitelisted tables allowed."""
    if table not in _EXPORTABLE_TABLES:
        raise HTTPException(status_code=400, detail=f"Table not exportable. Allowed: {sorted(_EXPORTABLE_TABLES)}")
    store = get_store()
    conn = store._get_conn()
    try:
        if client_id:
            rows = conn.execute(f"SELECT * FROM {table} WHERE client_id = ?", (client_id,)).fetchall()
        else:
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()
    except Exception:
        # Fallback: table may not have client_id column
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
    logger.info("Exported table %s (%d rows)", table, len(rows))
    return [dict(r) for r in rows]


# -----------------------------------------------------------------------
# Extended Health
# -----------------------------------------------------------------------


@router.get("/admin/health")
async def admin_health(_user=Depends(require_permission("admin:read"))):
    """Extended health check with system details. Admin only."""
    store = get_store()
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
async def list_users(
    offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500), _user=Depends(require_permission("admin:read"))
):
    """List all users. Admin only."""
    store = get_store()
    users = store.list_users()
    return [UserPublic(**u.model_dump()) for u in users[offset : offset + limit]]


@router.post("/admin/users", response_model=UserPublic)
async def create_user(req: AdminCreateUser, _user=Depends(require_permission("admin:write"))):
    """Create a new user. Admin only."""
    from kryon.server.auth.models import User

    complexity_error = validate_password_complexity(req.password)
    if complexity_error:
        raise HTTPException(status_code=400, detail=complexity_error)

    store = get_store()

    # Check uniqueness
    if store.get_user_by_username(req.username):
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username=req.username,
        email=req.email,
        password_hash=hash_password(req.password),
        role=req.role,
    )
    store.create_user(user)
    logger.info("User created: %s role=%s", req.username, req.role)
    return UserPublic(**user.model_dump())


@router.put("/admin/users/{user_id}", response_model=UserPublic)
async def update_user(user_id: str, req: AdminUpdateUser, _user=Depends(require_permission("admin:write"))):
    """Update a user. Admin only."""
    store = get_store()
    existing = store.get_user_by_id(user_id)
    if not existing:
        logger.warning("User not found: %s", user_id)
        raise not_found("User", user_id)

    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    store.update_user(user_id, **updates)
    logger.info("User updated: %s fields=%s", user_id, list(updates.keys()))
    updated = store.get_user_by_id(user_id)
    return UserPublic(**updated.model_dump())


@router.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, _user=Depends(require_permission("admin:write"))):
    """Delete a user. Admin only."""
    store = get_store()
    if not store.delete_user(user_id):
        logger.warning("User not found for delete: %s", user_id)
        raise not_found("User", user_id)
    logger.info("User deleted: %s", user_id)
    return {"deleted": True}
