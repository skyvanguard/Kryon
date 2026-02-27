"""Scope whitelist management endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.auth.rbac import require_permission
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found

router = APIRouter(tags=["scope"], dependencies=[Depends(require_api_key)])


class CreateScopeRuleRequest(BaseModel):
    client_id: str
    rule_type: str = Field(..., pattern="^(cidr|domain|ip|url_prefix)$")
    value: str = Field(..., min_length=1, max_length=500)
    description: str = ""


class ScopeRuleResponse(BaseModel):
    id: str
    client_id: str
    rule_type: str
    value: str
    description: str
    created_at: str
    created_by: str | None


@router.post("/scope/rules", response_model=ScopeRuleResponse, dependencies=[Depends(require_permission("scope:write"))])
async def create_scope_rule(req: CreateScopeRuleRequest) -> ScopeRuleResponse:
    """Create a new scope whitelist rule."""
    store = get_store()
    rule_id = uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()
    store.create_scope_rule(rule_id, req.client_id, req.rule_type, req.value, req.description, now)
    return ScopeRuleResponse(
        id=rule_id, client_id=req.client_id, rule_type=req.rule_type,
        value=req.value, description=req.description, created_at=now, created_by=None,
    )


@router.get("/scope/rules", dependencies=[Depends(require_permission("scope:read"))])
async def list_scope_rules(client_id: str | None = None, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500)) -> list[ScopeRuleResponse]:
    """List scope whitelist rules, optionally filtered by client."""
    store = get_store()
    rows = store.list_scope_rules(client_id=client_id, offset=offset, limit=limit)
    return [ScopeRuleResponse(**r) for r in rows]


@router.get("/scope/rules/{rule_id}", dependencies=[Depends(require_permission("scope:read"))])
async def get_scope_rule(rule_id: str) -> ScopeRuleResponse:
    """Get a single scope rule by ID."""
    store = get_store()
    row = store.get_scope_rule(rule_id)
    if not row:
        raise not_found("Scope rule", rule_id)
    return ScopeRuleResponse(**row)


@router.delete("/scope/rules/{rule_id}", dependencies=[Depends(require_permission("scope:write"))])
async def delete_scope_rule(rule_id: str) -> dict:
    """Delete a scope whitelist rule."""
    store = get_store()
    deleted = store.delete_scope_rule(rule_id)
    if not deleted:
        raise not_found("Scope rule", rule_id)
    return {"deleted": True, "id": rule_id}
