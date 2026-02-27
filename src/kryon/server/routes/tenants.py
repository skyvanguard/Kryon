"""Tenant management endpoints (admin only)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.auth.rbac import require_permission
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found

router = APIRouter(tags=["admin"], dependencies=[Depends(require_api_key)])


class CreateTenantRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=50, pattern="^[a-z0-9-]+$")
    tier: str = "free"


class TenantResponse(BaseModel):
    id: str
    name: str
    slug: str
    tier: str
    is_active: bool
    created_at: str


@router.post("/tenants", response_model=TenantResponse, dependencies=[Depends(require_permission("admin:write"))])
async def create_tenant(req: CreateTenantRequest) -> TenantResponse:
    """Create a new tenant."""
    store = get_store()
    tenant_id = uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()
    store.create_tenant({
        "id": tenant_id, "name": req.name, "slug": req.slug,
        "tier": req.tier, "is_active": True, "config_json": {},
        "created_at": now,
    })
    return TenantResponse(
        id=tenant_id, name=req.name, slug=req.slug,
        tier=req.tier, is_active=True, created_at=now,
    )


@router.get("/tenants", dependencies=[Depends(require_permission("admin:read"))])
async def list_tenants() -> list[TenantResponse]:
    """List all tenants."""
    store = get_store()
    tenants = store.list_tenants()
    return [TenantResponse(
        id=t["id"], name=t["name"], slug=t["slug"],
        tier=t.get("tier", "free"), is_active=bool(t.get("is_active", True)),
        created_at=t["created_at"],
    ) for t in tenants]


@router.get("/tenants/{tenant_id}", dependencies=[Depends(require_permission("admin:read"))])
async def get_tenant(tenant_id: str) -> TenantResponse:
    """Get a tenant by ID."""
    store = get_store()
    t = store.get_tenant(tenant_id)
    if not t:
        raise not_found("Tenant", tenant_id)
    return TenantResponse(
        id=t["id"], name=t["name"], slug=t["slug"],
        tier=t.get("tier", "free"), is_active=bool(t.get("is_active", True)),
        created_at=t["created_at"],
    )


@router.delete("/tenants/{tenant_id}", dependencies=[Depends(require_permission("admin:write"))])
async def delete_tenant(tenant_id: str) -> dict:
    """Delete a tenant and all associated data."""
    store = get_store()
    deleted = store.delete_tenant(tenant_id)
    if not deleted:
        raise not_found("Tenant", tenant_id)
    return {"deleted": True, "id": tenant_id}
