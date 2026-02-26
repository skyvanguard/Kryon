"""Engagement API endpoints — multi-day autonomous pentesting operations."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from kryon.server.auth import require_api_key
from kryon.server.models import CreateEngagementRequest, EngagementResponse

router = APIRouter(tags=["engagements"], dependencies=[Depends(require_api_key)])

# Lazy singleton manager
_manager = None


def _get_manager():
    global _manager
    if _manager is None:
        from kryon.engagements.manager import EngagementManager

        _manager = EngagementManager()
    return _manager


@router.post("/engagements", response_model=EngagementResponse)
async def create_engagement(req: CreateEngagementRequest) -> EngagementResponse:
    """Create a new multi-day engagement."""
    from kryon.engagements.models import Engagement

    engagement = Engagement(
        client_name=req.client_name,
        targets=req.targets,
        objectives=req.objectives,
        duration_days=req.duration_days,
        stealth_level=req.stealth_level,
        phase_interval_minutes=req.phase_interval_minutes,
    )

    manager = _get_manager()
    eng = await manager.create_engagement(engagement)
    return EngagementResponse(
        id=eng.id, status=eng.status.value, message="Engagement created, planning started"
    )


@router.get("/engagements")
async def list_engagements(status: str | None = None) -> list[dict]:
    """List all engagements, optionally filtered by status."""
    manager = _get_manager()
    status_filter = [status] if status else None
    engagements = manager._store.list_engagements(status_filter=status_filter)
    return [e.model_dump(mode="json") for e in engagements]


@router.get("/engagements/{engagement_id}")
async def get_engagement(engagement_id: str) -> dict:
    """Get engagement detail with phases."""
    manager = _get_manager()
    eng = manager._store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    phases = manager._store.get_engagement_phases(engagement_id)
    result = eng.model_dump(mode="json")
    result["phases"] = [p.model_dump(mode="json") for p in phases]
    return result


@router.get("/engagements/{engagement_id}/stream")
async def stream_engagement(engagement_id: str):
    """SSE stream for live engagement updates."""
    manager = _get_manager()
    eng = manager._store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")

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

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/engagements/{engagement_id}/findings")
async def get_engagement_findings(engagement_id: str) -> list[dict]:
    """Get accumulated findings across all engagement phases."""
    manager = _get_manager()
    eng = manager._store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")

    phases = manager._store.get_engagement_phases(engagement_id)
    all_findings = []
    for phase in phases:
        if phase.scan_id:
            findings = manager._store.get_findings(phase.scan_id)
            all_findings.extend([f.model_dump(mode="json") for f in findings])
    return all_findings


@router.post("/engagements/{engagement_id}/pause")
async def pause_engagement(engagement_id: str) -> dict:
    """Pause an active engagement."""
    manager = _get_manager()
    eng = manager._store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    await manager.pause_engagement(engagement_id)
    return {"status": "paused"}


@router.post("/engagements/{engagement_id}/resume")
async def resume_engagement(engagement_id: str) -> dict:
    """Resume a paused engagement."""
    manager = _get_manager()
    eng = manager._store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    await manager.resume_engagement(engagement_id)
    return {"status": "active"}


@router.delete("/engagements/{engagement_id}")
async def cancel_engagement(engagement_id: str) -> dict:
    """Cancel an engagement."""
    manager = _get_manager()
    eng = manager._store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    await manager.cancel_engagement(engagement_id)
    return {"status": "cancelled"}
