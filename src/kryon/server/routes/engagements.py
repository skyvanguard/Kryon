"""Engagement API endpoints — multi-day autonomous pentesting operations."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query

from kryon.server.auth import require_api_key
from kryon.server.auth.deps import get_current_user
from kryon.server.auth.isolation import verify_client_access
from kryon.server.auth.models import User
from kryon.server.deps import get_engagement_manager
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger
from kryon.server.models import CreateEngagementRequest, EngagementResponse
from kryon.server.sse import sse_response

logger = get_logger(__name__)

router = APIRouter(tags=["engagements"], dependencies=[Depends(require_api_key)])


@router.post("/engagements", response_model=EngagementResponse)
async def create_engagement(
    req: CreateEngagementRequest, user: User | None = Depends(get_current_user)
) -> EngagementResponse:
    """Create a new multi-day engagement."""
    from kryon.engagements.models import Engagement

    verify_client_access(user, req.client_name, get_engagement_manager().store)

    engagement = Engagement(
        client_name=req.client_name,
        targets=req.targets,
        objectives=req.objectives,
        duration_days=req.duration_days,
        stealth_level=req.stealth_level,
        phase_interval_minutes=req.phase_interval_minutes,
    )

    manager = get_engagement_manager()
    eng = await manager.create_engagement(engagement)
    logger.info("Engagement created: id=%s client=%s targets=%d", eng.id, req.client_name, len(req.targets))
    return EngagementResponse(id=eng.id, status=eng.status.value, message="Engagement created, planning started")


@router.get("/engagements")
async def list_engagements(
    status: str | None = None, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500)
) -> list[dict]:
    """List all engagements, optionally filtered by status."""
    manager = get_engagement_manager()
    status_filter = [status] if status else None
    engagements = manager.store.list_engagements(status_filter=status_filter, offset=offset, limit=limit)
    return [e.model_dump(mode="json") for e in engagements]


@router.get("/engagements/{engagement_id}")
async def get_engagement(engagement_id: str) -> dict:
    """Get engagement detail with phases."""
    manager = get_engagement_manager()
    eng = manager.store.get_engagement(engagement_id)
    if not eng:
        logger.warning("Engagement not found: %s", engagement_id)
        raise not_found("Engagement", engagement_id)
    phases = manager.store.get_engagement_phases(engagement_id)
    result = eng.model_dump(mode="json")
    result["phases"] = [p.model_dump(mode="json") for p in phases]
    return result


@router.get("/engagements/{engagement_id}/stream")
async def stream_engagement(engagement_id: str):
    """SSE stream for live engagement updates."""
    manager = get_engagement_manager()
    eng = manager.store.get_engagement(engagement_id)
    if not eng:
        raise not_found("Engagement", engagement_id)

    async def _event_generator():
        queue = manager.get_progress_queue(engagement_id)
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                event_type = event.get("event", "update")
                data = json.dumps(event.get("data", {}), default=str)
                yield f"event: {event_type}\ndata: {data}\n\n"
                if event_type == "done":
                    break
            except asyncio.TimeoutError:
                yield "event: ping\ndata: {}\n\n"

    return sse_response(_event_generator())


@router.get("/engagements/{engagement_id}/findings")
async def get_engagement_findings(engagement_id: str) -> list[dict]:
    """Get accumulated findings across all engagement phases."""
    manager = get_engagement_manager()
    eng = manager.store.get_engagement(engagement_id)
    if not eng:
        raise not_found("Engagement", engagement_id)

    phases = manager.store.get_engagement_phases(engagement_id)
    all_findings = []
    for phase in phases:
        if phase.scan_id:
            findings = manager.store.get_findings(phase.scan_id)
            all_findings.extend([f.model_dump(mode="json") for f in findings])
    return all_findings


@router.post("/engagements/{engagement_id}/pause")
async def pause_engagement(engagement_id: str) -> dict:
    """Pause an active engagement."""
    manager = get_engagement_manager()
    eng = manager.store.get_engagement(engagement_id)
    if not eng:
        raise not_found("Engagement", engagement_id)
    if eng.status.value != "active":
        raise HTTPException(status_code=409, detail=f"Cannot pause engagement in '{eng.status.value}' state")
    await manager.pause_engagement(engagement_id)
    logger.info("Engagement paused: %s", engagement_id)
    return {"status": "paused"}


@router.post("/engagements/{engagement_id}/resume")
async def resume_engagement(engagement_id: str) -> dict:
    """Resume a paused engagement."""
    manager = get_engagement_manager()
    eng = manager.store.get_engagement(engagement_id)
    if not eng:
        raise not_found("Engagement", engagement_id)
    if eng.status.value != "paused":
        raise HTTPException(status_code=409, detail=f"Cannot resume engagement in '{eng.status.value}' state")
    await manager.resume_engagement(engagement_id)
    logger.info("Engagement resumed: %s", engagement_id)
    return {"status": "active"}


@router.delete("/engagements/{engagement_id}")
async def cancel_engagement(engagement_id: str) -> dict:
    """Cancel an engagement."""
    manager = get_engagement_manager()
    eng = manager.store.get_engagement(engagement_id)
    if not eng:
        raise not_found("Engagement", engagement_id)
    await manager.cancel_engagement(engagement_id)
    logger.info("Engagement cancelled: %s", engagement_id)
    return {"status": "cancelled"}
