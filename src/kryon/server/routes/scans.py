"""Scan management API endpoints — scheduled scans + autonomous auto-scans."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, Query

from kryon.server.auth import require_api_key
from kryon.server.auth.deps import get_current_user
from kryon.server.auth.isolation import (
    get_accessible_client_ids,
    require_resource_access,
    verify_client_access,
)
from kryon.server.auth.models import User
from kryon.server.deps import get_scheduler, get_store
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger
from kryon.server.models import (
    AutoScanFinding,
    AutoScanRequest,
    AutoScanResponse,
    AutoScanStatus,
    ScheduleScanRequest,
)
from kryon.server.sse import sse_response

logger = get_logger(__name__)

router = APIRouter(tags=["scans"], dependencies=[Depends(require_api_key)])

# ---------------------------------------------------------------------------
# Scheduled scans (existing)
# ---------------------------------------------------------------------------


@router.post("/scans")
async def schedule_scan(req: ScheduleScanRequest, user: User | None = Depends(get_current_user)) -> dict:
    """Schedule a new scan."""
    verify_client_access(user, req.client_id, get_store())
    scheduler = get_scheduler()
    job_id = await scheduler.schedule_scan(
        client_id=req.client_id,
        agent_key=req.agent_key,
        profile=req.profile,
        interval_seconds=req.interval_seconds,
        cron=req.cron,
        webhook_url=req.webhook_url,
    )
    logger.info("Scan scheduled: job=%s client=%s agent=%s", job_id, req.client_id, req.agent_key)
    return {"job_id": job_id, "status": "scheduled"}


@router.get("/scans")
async def list_scans(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    user: User | None = Depends(get_current_user),
) -> list[dict]:
    """List all scheduled and completed scans."""
    scheduler = get_scheduler()
    jobs = await scheduler.list_scheduled()
    # Scope non-admin users to their assigned clients.
    accessible = get_accessible_client_ids(user, get_store())
    if accessible is not None:
        jobs = [j for j in jobs if j.client_id in accessible]
    return [j.model_dump() for j in jobs[offset : offset + limit]]


@router.get("/scans/{job_id}")
async def get_scan(job_id: str, user: User | None = Depends(get_current_user)) -> dict:
    """Get scan job details."""
    scheduler = get_scheduler()
    job = scheduler.jobs.get(job_id)
    if not job:
        logger.warning("Scan job not found: %s", job_id)
        raise not_found("Job", job_id)
    require_resource_access(user, job.client_id, get_store(), kind="Job", resource_id=job_id)
    return job.model_dump()


@router.delete("/scans/{job_id}")
async def cancel_scan(job_id: str, user: User | None = Depends(get_current_user)) -> dict:
    """Cancel a scheduled scan."""
    scheduler = get_scheduler()
    # Authorize against the job's client before cancelling, so a scoped
    # user cannot cancel another client's scan by guessing its ID.
    job = scheduler.jobs.get(job_id)
    if not job:
        logger.warning("Scan job not found for cancel: %s", job_id)
        raise not_found("Job", job_id)
    require_resource_access(user, job.client_id, get_store(), kind="Job", resource_id=job_id)
    if not await scheduler.cancel_scan(job_id):
        raise not_found("Job", job_id)
    logger.info("Scan cancelled: %s", job_id)
    return {"cancelled": True}


# ---------------------------------------------------------------------------
# Autonomous auto-scans
# ---------------------------------------------------------------------------

# In-memory registry of running/completed auto-scans (protected by asyncio.Lock)
_auto_scans: dict[str, dict] = {}  # scan_id -> {"orchestrator": ..., "task": ..., "progress": ...}
_auto_scans_lock = asyncio.Lock()
_AUTO_SCANS_MAX = 50


async def _cleanup_completed_scans() -> None:
    """Remove completed/failed scan entries when the registry grows too large."""
    if len(_auto_scans) <= _AUTO_SCANS_MAX:
        return
    done_ids = [sid for sid, entry in _auto_scans.items() if entry["task"].done()]
    for sid in done_ids:
        _auto_scans.pop(sid, None)


@router.post("/scans/auto", response_model=AutoScanResponse)
async def start_auto_scan(req: AutoScanRequest, user: User | None = Depends(get_current_user)) -> AutoScanResponse:
    """Start an autonomous enterprise pentest in the background."""
    verify_client_access(user, req.client_id, get_store())
    async with _auto_scans_lock:
        await _cleanup_completed_scans()

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
            logger.exception("Auto-scan background task failed: scan_id=%s", scan_id)

    task = asyncio.create_task(_run_scan())
    async with _auto_scans_lock:
        _auto_scans[scan_id] = {
            "orchestrator": orch,
            "task": task,
        }

    logger.info("Auto-scan started: id=%s client=%s targets=%d", scan_id, req.client_id, len(req.targets))
    return AutoScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Autonomous scan started with {len(orch.targets)} target(s), profile={req.profile}",
    )


@router.get("/scans/auto/{scan_id}", response_model=AutoScanStatus)
async def get_auto_scan_status(scan_id: str, user: User | None = Depends(get_current_user)) -> AutoScanStatus:
    """Get current status of an autonomous scan."""
    entry = _auto_scans.get(scan_id)
    if not entry:
        raise not_found("Auto-scan", scan_id)
    require_resource_access(user, entry["orchestrator"].client_id, get_store(), kind="Auto-scan", resource_id=scan_id)

    p = entry["orchestrator"].progress
    return AutoScanStatus(**p.to_dict())


@router.get("/scans/auto/{scan_id}/stream")
async def stream_auto_scan(scan_id: str, user: User | None = Depends(get_current_user)):
    """SSE stream of progress events for a running auto-scan."""
    entry = _auto_scans.get(scan_id)
    if not entry:
        raise not_found("Auto-scan", scan_id)
    require_resource_access(user, entry["orchestrator"].client_id, get_store(), kind="Auto-scan", resource_id=scan_id)

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

    return sse_response(_event_generator())


@router.get("/scans/auto/{scan_id}/findings", response_model=list[AutoScanFinding])
async def get_auto_scan_findings(scan_id: str, user: User | None = Depends(get_current_user)) -> list[AutoScanFinding]:
    """Get findings from an autonomous scan."""
    entry = _auto_scans.get(scan_id)
    if not entry:
        raise not_found("Auto-scan", scan_id)
    require_resource_access(user, entry["orchestrator"].client_id, get_store(), kind="Auto-scan", resource_id=scan_id)

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
        for f in orch.findings
    ]


@router.delete("/scans/auto/{scan_id}")
async def cancel_auto_scan(scan_id: str, user: User | None = Depends(get_current_user)) -> dict:
    """Cancel a running autonomous scan."""
    entry = _auto_scans.get(scan_id)
    if not entry:
        logger.warning("Auto-scan not found for cancel: %s", scan_id)
        raise not_found("Auto-scan", scan_id)
    require_resource_access(user, entry["orchestrator"].client_id, get_store(), kind="Auto-scan", resource_id=scan_id)

    task = entry["task"]
    if not task.done():
        task.cancel()
    _auto_scans.pop(scan_id, None)

    logger.info("Auto-scan cancelled: %s", scan_id)
    return {"scan_id": scan_id, "status": "cancelled"}
