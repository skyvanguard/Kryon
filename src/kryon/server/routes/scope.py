"""Scope whitelist management endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.auth.deps import get_current_user
from kryon.server.auth.isolation import get_accessible_client_ids, require_resource_access, verify_client_access
from kryon.server.auth.models import User
from kryon.server.auth.rbac import require_permission
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

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


@router.post(
    "/scope/rules", response_model=ScopeRuleResponse, dependencies=[Depends(require_permission("scope:write"))]
)
async def create_scope_rule(
    req: CreateScopeRuleRequest, user: User | None = Depends(get_current_user)
) -> ScopeRuleResponse:
    """Create a new scope whitelist rule."""
    store = get_store()
    # client_id is operator-supplied — verify ownership so a scoped user can't paint
    # ANOTHER client's network in-scope (the BOLA the route-level permission missed).
    verify_client_access(user, req.client_id, store)
    rule_id = uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()
    store.create_scope_rule(rule_id, req.client_id, req.rule_type, req.value, req.description, now)
    logger.info("Scope rule created: id=%s client=%s type=%s", rule_id, req.client_id, req.rule_type)
    return ScopeRuleResponse(
        id=rule_id,
        client_id=req.client_id,
        rule_type=req.rule_type,
        value=req.value,
        description=req.description,
        created_at=now,
        created_by=None,
    )


@router.get("/scope/rules", dependencies=[Depends(require_permission("scope:read"))])
async def list_scope_rules(
    client_id: str | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    user: User | None = Depends(get_current_user),
) -> list[ScopeRuleResponse]:
    """List scope whitelist rules, optionally filtered by client."""
    store = get_store()
    accessible = get_accessible_client_ids(user, store)
    if accessible is not None:
        # Scoped user: never return another client's rules.
        if client_id is not None and client_id not in accessible:
            raise not_found("Scope rule", client_id)
        rows = store.list_scope_rules(client_id=client_id, offset=offset, limit=limit)
        rows = [r for r in rows if r.get("client_id") in accessible]
    else:
        rows = store.list_scope_rules(client_id=client_id, offset=offset, limit=limit)
    return [ScopeRuleResponse(**r) for r in rows]


@router.get("/scope/rules/{rule_id}", dependencies=[Depends(require_permission("scope:read"))])
async def get_scope_rule(rule_id: str, user: User | None = Depends(get_current_user)) -> ScopeRuleResponse:
    """Get a single scope rule by ID."""
    store = get_store()
    row = store.get_scope_rule(rule_id)
    if not row:
        logger.warning("Scope rule not found: %s", rule_id)
        raise not_found("Scope rule", rule_id)
    require_resource_access(user, row["client_id"], store, kind="Scope rule", resource_id=rule_id)
    return ScopeRuleResponse(**row)


@router.delete("/scope/rules/{rule_id}", dependencies=[Depends(require_permission("scope:write"))])
async def delete_scope_rule(rule_id: str, user: User | None = Depends(get_current_user)) -> dict:
    """Delete a scope whitelist rule."""
    store = get_store()
    row = store.get_scope_rule(rule_id)
    if not row:
        logger.warning("Scope rule not found for delete: %s", rule_id)
        raise not_found("Scope rule", rule_id)
    require_resource_access(user, row["client_id"], store, kind="Scope rule", resource_id=rule_id)
    deleted = store.delete_scope_rule(rule_id)
    if not deleted:
        logger.warning("Scope rule not found for delete: %s", rule_id)
        raise not_found("Scope rule", rule_id)
    logger.info("Scope rule deleted: %s", rule_id)
    return {"deleted": True, "id": rule_id}
