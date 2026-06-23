"""Remediation workflow API — assignment, notes, retest, SLA, MTTR."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.auth.deps import get_current_user
from kryon.server.auth.isolation import get_accessible_client_ids, require_resource_access
from kryon.server.auth.models import User
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["remediation"], dependencies=[Depends(require_api_key)])


class AssignBody(BaseModel):
    assigned_to: str = Field(..., min_length=1, max_length=200)
    priority: str = Field("medium", pattern=r"^(critical|high|medium|low)$")


class NoteBody(BaseModel):
    note: str = Field(..., min_length=1, max_length=5000)


class RetestBody(BaseModel):
    agent_key: str = Field(..., min_length=1, max_length=100)
    targets: list[str] = Field(default=[], max_length=100)


@router.put("/remediation/findings/{finding_id}/assign")
async def assign_finding(
    finding_id: str, body: AssignBody, user: User | None = Depends(get_current_user)
) -> dict:
    """Assign a finding and auto-calculate SLA deadline."""
    store = get_store()
    finding = store.get_finding_by_id(finding_id)
    if not finding:
        logger.warning("Finding not found for assign: %s", finding_id)
        raise not_found("Finding", finding_id)
    require_resource_access(user, finding.client_id, store, kind="Finding", resource_id=finding_id)

    from kryon.remediation.sla import calculate_sla_deadline

    now = datetime.now(timezone.utc)
    sla_deadline = calculate_sla_deadline(body.priority, now)

    store.assign_finding(
        finding_id=finding_id,
        assigned_to=body.assigned_to,
        priority=body.priority,
        sla_deadline=sla_deadline,
        assigned_at=now.isoformat(),
    )
    logger.info("Finding assigned: id=%s to=%s priority=%s", finding_id, body.assigned_to, body.priority)
    return {"id": finding_id, "assigned_to": body.assigned_to, "priority": body.priority, "sla_deadline": sla_deadline}


@router.post("/remediation/findings/{finding_id}/note")
async def add_note(finding_id: str, body: NoteBody, user: User | None = Depends(get_current_user)) -> dict:
    """Add a remediation note to a finding."""
    store = get_store()
    # Resolve + authorize before mutating, so a scoped user cannot append a
    # note to another client's finding by guessing its ID.
    finding = store.get_finding_by_id(finding_id)
    if not finding:
        logger.warning("Finding not found for note: %s", finding_id)
        raise not_found("Finding", finding_id)
    require_resource_access(user, finding.client_id, store, kind="Finding", resource_id=finding_id)
    if not store.add_remediation_note(finding_id, body.note):
        logger.warning("Finding not found for note: %s", finding_id)
        raise not_found("Finding", finding_id)
    logger.info("Remediation note added: finding=%s", finding_id)
    return {"id": finding_id, "note_added": True}


@router.post("/remediation/findings/{finding_id}/retest")
async def schedule_retest(
    finding_id: str, body: RetestBody, user: User | None = Depends(get_current_user)
) -> dict:
    """Schedule a retest scan for a finding."""
    store = get_store()
    finding = store.get_finding_by_id(finding_id)
    if not finding:
        logger.warning("Finding not found for retest: %s", finding_id)
        raise not_found("Finding", finding_id)
    require_resource_access(user, finding.client_id, store, kind="Finding", resource_id=finding_id)
    # Mark retest status
    conn = store._get_conn()
    conn.execute("UPDATE findings SET retest_status = 'scheduled' WHERE id = ?", (finding_id,))
    conn.commit()
    logger.info("Retest scheduled: finding=%s agent=%s", finding_id, body.agent_key)
    return {"id": finding_id, "retest_status": "scheduled", "agent_key": body.agent_key}


@router.get("/remediation/overdue")
async def list_overdue(
    client_id: str = "",
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    user: User | None = Depends(get_current_user),
) -> dict:
    """List findings past their SLA deadline."""
    store = get_store()
    # Restrict scoped users to their assigned clients. The store filters by a
    # single client_id, so a scoped user must name one of theirs.
    accessible = get_accessible_client_ids(user, store)
    if accessible is not None:
        if not client_id:
            if len(accessible) == 1:
                client_id = next(iter(accessible))
            else:
                raise not_found("Findings", "scope")
        elif client_id not in accessible:
            raise not_found("Findings", client_id)
    items = store.get_overdue_findings(client_id=client_id, offset=offset, limit=limit)
    return {"items": [f.model_dump() for f in items], "offset": offset, "limit": limit}


@router.get("/remediation/metrics")
async def get_metrics(client_id: str = "", user: User | None = Depends(get_current_user)) -> dict:
    """Get remediation metrics including MTTR and SLA compliance."""
    from kryon.remediation.sla import calculate_mttr

    store = get_store()
    accessible = get_accessible_client_ids(user, store)
    if accessible is not None:
        if not client_id:
            if len(accessible) == 1:
                client_id = next(iter(accessible))
            else:
                raise not_found("Findings", "scope")
        elif client_id not in accessible:
            raise not_found("Findings", client_id)
    return calculate_mttr(store, client_id=client_id)


@router.get("/remediation/findings/{finding_id}/history")
async def get_history(finding_id: str, user: User | None = Depends(get_current_user)) -> list[dict]:
    """Get finding change history."""
    store = get_store()
    finding = store.get_finding_by_id(finding_id)
    if not finding:
        logger.warning("Finding not found for history: %s", finding_id)
        raise not_found("Finding", finding_id)
    require_resource_access(user, finding.client_id, store, kind="Finding", resource_id=finding_id)
    return store.get_finding_history_log(finding_id)
