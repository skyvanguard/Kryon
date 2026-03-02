"""Findings API — consolidated view of all security findings."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from kryon.server.auth import require_api_key
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
) -> dict:
    """List all findings with optional filtering and pagination."""
    store = get_store()
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
async def get_finding(finding_id: str) -> dict:
    """Get a specific finding by ID."""
    store = get_store()
    finding = store.get_finding_by_id(finding_id)
    if not finding:
        logger.warning("Finding not found: %s", finding_id)
        raise not_found("Finding", finding_id)
    return finding.model_dump()


@router.put("/findings/{finding_id}/status")
async def update_finding_status(finding_id: str, body: dict) -> dict:
    """Update finding status (open, remediated, accepted, false_positive)."""
    new_status = body.get("status", "")
    allowed = {"open", "remediated", "accepted", "false_positive"}
    if new_status not in allowed:
        from fastapi import HTTPException

        raise HTTPException(400, f"Invalid status. Must be one of: {allowed}")
    store = get_store()
    if not store.update_finding_status(finding_id, new_status):
        logger.warning("Finding not found for status update: %s", finding_id)
        raise not_found("Finding", finding_id)
    logger.info("Finding status updated: id=%s status=%s", finding_id, new_status)
    return {"id": finding_id, "status": new_status}
