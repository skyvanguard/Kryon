"""Scan scheduling — asyncio-based job scheduler with DB persistence."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Callable, Coroutine

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


def _get_store():
    """Lazy import to avoid circular dependencies."""
    from kryon.server.deps import get_store
    return get_store()


class ScheduledJob(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    client_id: str
    agent_key: str
    profile: str = "standard"
    cron: str = ""  # Cron expression (for display only in asyncio version)
    interval_seconds: int = 0  # Actual scheduling interval
    webhook_url: str | None = None
    status: str = "scheduled"  # scheduled, running, completed, cancelled
    next_run: str = ""
    last_run: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ScanScheduler:
    """Schedule recurring security scans using asyncio tasks."""

    def __init__(self) -> None:
        self.jobs: dict[str, ScheduledJob] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._scan_callback: Callable[..., Coroutine] | None = None

    def set_scan_callback(self, callback: Callable[..., Coroutine]) -> None:
        """Set the callback that actually runs a scan."""
        self._scan_callback = callback

    async def schedule_scan(
        self,
        client_id: str,
        agent_key: str,
        profile: str = "standard",
        interval_seconds: int = 604800,  # Default: weekly
        cron: str = "",
        webhook_url: str | None = None,
    ) -> str:
        """Schedule a recurring scan. Returns job_id."""
        job = ScheduledJob(
            client_id=client_id,
            agent_key=agent_key,
            profile=profile,
            interval_seconds=interval_seconds,
            cron=cron,
            webhook_url=webhook_url,
        )
        self.jobs[job.id] = job

        # Persist to DB
        try:
            _get_store().save_scheduled_job(job.model_dump())
        except Exception:
            logger.warning("Failed to persist job %s to DB", job.id, exc_info=True)

        task = asyncio.create_task(self._run_loop(job))
        self._tasks[job.id] = task
        logger.info("Scheduled scan job %s for client %s every %ds", job.id, client_id, interval_seconds)
        return job.id

    async def cancel_scan(self, job_id: str) -> bool:
        """Cancel a scheduled scan."""
        if job_id not in self.jobs:
            return False
        self.jobs[job_id].status = "cancelled"
        if job_id in self._tasks:
            self._tasks[job_id].cancel()
            del self._tasks[job_id]

        # Update DB
        try:
            _get_store().update_scheduled_job_status(job_id, "cancelled")
        except Exception:
            logger.warning("Failed to update job %s status in DB", job_id, exc_info=True)
        return True

    async def restore_from_db(self) -> int:
        """Restore active scheduled jobs from database. Returns count restored."""
        try:
            store = _get_store()
            rows = store.list_scheduled_jobs(status="scheduled")
        except Exception:
            logger.warning("Failed to load scheduled jobs from DB", exc_info=True)
            return 0

        restored = 0
        for row in rows:
            if row["id"] in self.jobs:
                continue
            job = ScheduledJob(**row)
            self.jobs[job.id] = job
            task = asyncio.create_task(self._run_loop(job))
            self._tasks[job.id] = task
            restored += 1

        if restored:
            logger.info("Restored %d scheduled jobs from database", restored)
        return restored

    async def list_scheduled(self) -> list[ScheduledJob]:
        """List all scheduled jobs."""
        return list(self.jobs.values())

    async def run_scan_job(self, job: ScheduledJob) -> None:
        """Execute a single scan job."""
        job.status = "running"
        job.last_run = datetime.now(timezone.utc).isoformat()
        logger.info("Running scan job %s", job.id)

        try:
            if self._scan_callback:
                await self._scan_callback(
                    client_id=job.client_id,
                    agent_key=job.agent_key,
                    profile=job.profile,
                )

            # Send webhook notification if configured
            if job.webhook_url:
                await self._send_webhook(job)

            job.status = "scheduled"
        except Exception:
            logger.error("Scan job %s failed", job.id, exc_info=True)
            job.status = "scheduled"

    async def _run_loop(self, job: ScheduledJob) -> None:
        """Background loop for a scheduled job."""
        try:
            while job.status != "cancelled":
                await self.run_scan_job(job)
                # Persist last_run to DB
                try:
                    _get_store().update_scheduled_job_status(
                        job.id, job.status, last_run=job.last_run
                    )
                except Exception:
                    logger.debug("Failed to persist last_run for job %s", job.id)
                if job.interval_seconds > 0:
                    await asyncio.sleep(job.interval_seconds)
                else:
                    break  # One-shot
        except asyncio.CancelledError:
            job.status = "cancelled"

    async def _send_webhook(self, job: ScheduledJob) -> None:
        """Send webhook notification."""
        if not job.webhook_url:
            return
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    job.webhook_url,
                    json={
                        "event": "scan_completed",
                        "job_id": job.id,
                        "client_id": job.client_id,
                        "agent_key": job.agent_key,
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
        except Exception:
            logger.debug("Webhook delivery failed for job %s", job.id, exc_info=True)

    async def shutdown(self) -> None:
        """Cancel all running tasks."""
        for task in self._tasks.values():
            task.cancel()
        self._tasks.clear()
