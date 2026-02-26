"""Scan management API endpoints — scheduled scans + autonomous auto-scans."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from kryon.server.auth import require_api_key
from kryon.server.models import (
    AutoScanFinding,
    AutoScanRequest,
    AutoScanResponse,
    AutoScanStatus,
)

router = APIRouter(tags=["scans"], dependencies=[Depends(require_api_key)])

# ---------------------------------------------------------------------------
# Scheduled scans (existing)
# ---------------------------------------------------------------------------

import threading

# Lazy singleton scheduler (thread-safe)
_scheduler = None
_scheduler_lock = threading.Lock()


def _get_scheduler():
    global _scheduler
    if _scheduler is None:
        with _scheduler_lock:
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


# ---------------------------------------------------------------------------
# Autonomous auto-scans
# ---------------------------------------------------------------------------

# In-memory registry of running/completed auto-scans
_auto_scans: dict[str, dict] = {}  # scan_id -> {"orchestrator": ..., "task": ..., "progress": ...}


@router.post("/scans/auto", response_model=AutoScanResponse)
async def start_auto_scan(req: AutoScanRequest) -> AutoScanResponse:
    """Start an autonomous enterprise pentest in the background."""
    from kryon.providers.rate_limiter import RateLimiter
    from kryon.tools.autonomous.enterprise_orchestrator import EnterpriseOrchestrator

    rate_limiter = RateLimiter.detect_provider()

    orch = EnterpriseOrchestrator(
        scope=req.targets,
        client_id=req.client_id,
        client_name=req.client_id,
        profile=req.profile,
        max_time_hours=req.max_time_hours,
        stealth_level=req.stealth_level,
        rate_limiter=rate_limiter,
        output_format=req.output_format,
        compliance_frameworks=req.compliance_frameworks,
    )

    scan_id = orch.progress.scan_id

    async def _run_scan():
        try:
            await orch.run()
        except Exception:
            pass  # errors are captured in progress

    task = asyncio.create_task(_run_scan())
    _auto_scans[scan_id] = {
        "orchestrator": orch,
        "task": task,
    }

    return AutoScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Autonomous scan started with {len(orch.targets)} target(s), profile={req.profile}",
    )


@router.get("/scans/auto/{scan_id}", response_model=AutoScanStatus)
async def get_auto_scan_status(scan_id: str) -> AutoScanStatus:
    """Get current status of an autonomous scan."""
    entry = _auto_scans.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Auto-scan '{scan_id}' not found")

    p = entry["orchestrator"].progress
    return AutoScanStatus(**p.to_dict())


@router.get("/scans/auto/{scan_id}/stream")
async def stream_auto_scan(scan_id: str):
    """SSE stream of progress events for a running auto-scan."""
    entry = _auto_scans.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Auto-scan '{scan_id}' not found")

    async def _event_generator():
        orch = entry["orchestrator"]
        last_log_idx = 0

        while True:
            p = orch.progress
            data = p.to_dict()

            # Send full status event
            yield f"event: status\ndata: {json.dumps(data, default=str)}\n\n"

            # Send new log messages individually
            while last_log_idx < len(p.log_messages):
                log_msg = p.log_messages[last_log_idx]
                yield f"event: log\ndata: {json.dumps({'message': log_msg})}\n\n"
                last_log_idx += 1

            # Check if done
            if p.status in ("completed", "failed"):
                yield f"event: done\ndata: {json.dumps(data, default=str)}\n\n"
                break

            await asyncio.sleep(1.0)

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/scans/auto/{scan_id}/findings", response_model=list[AutoScanFinding])
async def get_auto_scan_findings(scan_id: str) -> list[AutoScanFinding]:
    """Get findings from an autonomous scan."""
    entry = _auto_scans.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Auto-scan '{scan_id}' not found")

    orch = entry["orchestrator"]
    return [
        AutoScanFinding(
            id=f.id,
            title=f.title,
            severity=f.severity.value,
            affected_asset=f.affected_asset,
            description=f.description[:500],
            cvss_score=f.cvss_score,
            tool_source=f.tool_source,
            remediation=f.remediation,
        )
        for f in orch._findings
    ]


@router.delete("/scans/auto/{scan_id}")
async def cancel_auto_scan(scan_id: str) -> dict:
    """Cancel a running autonomous scan."""
    entry = _auto_scans.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Auto-scan '{scan_id}' not found")

    task = entry["task"]
    if not task.done():
        task.cancel()

    return {"scan_id": scan_id, "status": "cancelled"}
