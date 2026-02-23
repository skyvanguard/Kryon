"""Scan management API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from kryon.server.auth import require_api_key

router = APIRouter(tags=["scans"], dependencies=[Depends(require_api_key)])

# Lazy singleton scheduler
_scheduler = None


def _get_scheduler():
    global _scheduler
    if _scheduler is None:
        from kryon.server.scheduler import ScanScheduler

        _scheduler = ScanScheduler()
    return _scheduler


class ScheduleScanRequest(BaseModel):
    client_id: str
    agent_key: str = "pentest_agent"
    profile: str = "standard"
    interval_seconds: int = 604800  # weekly
    cron: str = ""
    webhook_url: str | None = None


@router.post("/scans")
async def schedule_scan(req: ScheduleScanRequest) -> dict:
    """Schedule a new scan."""
    scheduler = _get_scheduler()
    job_id = await scheduler.schedule_scan(
        client_id=req.client_id,
        agent_key=req.agent_key,
        profile=req.profile,
        interval_seconds=req.interval_seconds,
        cron=req.cron,
        webhook_url=req.webhook_url,
    )
    return {"job_id": job_id, "status": "scheduled"}


@router.get("/scans")
async def list_scans() -> list[dict]:
    """List all scheduled and completed scans."""
    scheduler = _get_scheduler()
    jobs = await scheduler.list_scheduled()
    return [j.model_dump() for j in jobs]


@router.get("/scans/{job_id}")
async def get_scan(job_id: str) -> dict:
    """Get scan job details."""
    scheduler = _get_scheduler()
    job = scheduler.jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job.model_dump()


@router.delete("/scans/{job_id}")
async def cancel_scan(job_id: str) -> dict:
    """Cancel a scheduled scan."""
    scheduler = _get_scheduler()
    if not await scheduler.cancel_scan(job_id):
        raise HTTPException(status_code=404, detail="Job not found")
    return {"cancelled": True}
