"""Findings API — consolidated view of all security findings."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from kryon.server.auth import require_api_key
from kryon.server.auth.deps import get_current_user
from kryon.server.auth.isolation import get_accessible_client_ids, require_resource_access
from kryon.server.auth.models import User
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["findings"], dependencies=[Depends(require_api_key)])


@router.get("/findings")
async def list_findings(
    severity: str | None = None,
    status: str | None = None,
    client_id: str | None = None,
    tool_source: str | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    user: User | None = Depends(get_current_user),
) -> dict:
    """List all findings with optional filtering and pagination."""
    store = get_store()
    # Restrict non-admin users to their assigned clients. The store filters
    # by a single client_id, so we require one (and verify it) for scoped
    # users. Full multi-client list filtering needs store-level support
    # (tracked for the tenancy work) — single-tenant deployments are
    # unaffected since there is only one client.
    accessible = get_accessible_client_ids(user, store)
    if accessible is not None:
        if client_id is None:
            if len(accessible) == 1:
                client_id = next(iter(accessible))
            else:
                raise not_found("Findings", "scope")
        elif client_id not in accessible:
            raise not_found("Findings", client_id)
    items = store.list_all_findings(
        severity=severity,
        status=status,
        client_id=client_id,
        tool_source=tool_source,
        offset=offset,
        limit=limit,
    )
    total = store.count_findings(
        severity=severity,
        status=status,
        client_id=client_id,
        tool_source=tool_source,
    )
    return {
        "items": [f.model_dump() for f in items],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str, user: User | None = Depends(get_current_user)) -> dict:
    """Get a specific finding by ID."""
    store = get_store()
    finding = store.get_finding_by_id(finding_id)
    if not finding:
        logger.warning("Finding not found: %s", finding_id)
        raise not_found("Finding", finding_id)
    require_resource_access(user, finding.client_id, store, kind="Finding", resource_id=finding_id)
    return finding.model_dump()


class UpdateFindingStatus(BaseModel):
    status: Literal["open", "remediated", "accepted", "false_positive"]


@router.put("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: str, body: UpdateFindingStatus, user: User | None = Depends(get_current_user)
) -> dict:
    """Update finding status (open, remediated, accepted, false_positive)."""
    new_status = body.status
    store = get_store()
    # Resolve + authorize before mutating, so a scoped user cannot flip the
    # status of another client's finding by guessing its ID.
    finding = store.get_finding_by_id(finding_id)
    if not finding:
        logger.warning("Finding not found for status update: %s", finding_id)
        raise not_found("Finding", finding_id)
    require_resource_access(user, finding.client_id, store, kind="Finding", resource_id=finding_id)
    if not store.update_finding_status(finding_id, new_status):
        raise not_found("Finding", finding_id)
    logger.info("Finding status updated: id=%s status=%s", finding_id, new_status)
    return {"id": finding_id, "status": new_status}
