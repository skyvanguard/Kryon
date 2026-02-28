"""Remediation workflow API — assignment, notes, retest, SLA, MTTR."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found

router = APIRouter(tags=["remediation"], dependencies=[Depends(require_api_key)])


class AssignBody(BaseModel):
    assigned_to: str = Field(..., min_length=1, max_length=200)
    priority: str = Field("medium", pattern=r"^(critical|high|medium|low)$")


class NoteBody(BaseModel):
    note: str = Field(..., min_length=1, max_length=5000)


class RetestBody(BaseModel):
    agent_key: str = Field(..., min_length=1)
    targets: list[str] = []


@router.put("/remediation/findings/{finding_id}/assign")
async def assign_finding(finding_id: str, body: AssignBody) -> dict:
    """Assign a finding and auto-calculate SLA deadline."""
    store = get_store()
    finding = store.get_finding_by_id(finding_id)
    if not finding:
        raise not_found("Finding", finding_id)

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
    return {"id": finding_id, "assigned_to": body.assigned_to, "priority": body.priority, "sla_deadline": sla_deadline}


@router.post("/remediation/findings/{finding_id}/note")
async def add_note(finding_id: str, body: NoteBody) -> dict:
    """Add a remediation note to a finding."""
    store = get_store()
    if not store.add_remediation_note(finding_id, body.note):
        raise not_found("Finding", finding_id)
    return {"id": finding_id, "note_added": True}


@router.post("/remediation/findings/{finding_id}/retest")
async def schedule_retest(finding_id: str, body: RetestBody) -> dict:
    """Schedule a retest scan for a finding."""
    store = get_store()
    finding = store.get_finding_by_id(finding_id)
    if not finding:
        raise not_found("Finding", finding_id)
    # Mark retest status
    conn = store._get_conn()
    conn.execute("UPDATE findings SET retest_status = 'scheduled' WHERE id = ?", (finding_id,))
    conn.commit()
    return {"id": finding_id, "retest_status": "scheduled", "agent_key": body.agent_key}


@router.get("/remediation/overdue")
async def list_overdue(
    client_id: str = "",
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> dict:
    """List findings past their SLA deadline."""
    store = get_store()
    items = store.get_overdue_findings(client_id=client_id, offset=offset, limit=limit)
    return {"items": [f.model_dump() for f in items], "offset": offset, "limit": limit}


@router.get("/remediation/metrics")
async def get_metrics(client_id: str = "") -> dict:
    """Get remediation metrics including MTTR and SLA compliance."""
    from kryon.remediation.sla import calculate_mttr
    store = get_store()
    return calculate_mttr(store, client_id=client_id)


@router.get("/remediation/findings/{finding_id}/history")
async def get_history(finding_id: str) -> list[dict]:
    """Get finding change history."""
    store = get_store()
    return store.get_finding_history_log(finding_id)
