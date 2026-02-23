"""Job queue management for scan execution."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Job(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    client_id: str = ""
    agent_key: str = ""
    profile: str = "standard"
    prompt: str = ""
    status: JobStatus = JobStatus.QUEUED
    result: str = ""
    error: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: str = ""
    completed_at: str = ""


class JobQueue:
    """Simple async job queue for scan execution."""

    def __init__(self, max_concurrent: int = 3):
        self._queue: asyncio.Queue[Job] = asyncio.Queue()
        self._jobs: dict[str, Job] = {}
        self._max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._workers: list[asyncio.Task] = []

    async def submit(self, job: Job) -> str:
        """Submit a job to the queue. Returns job_id."""
        self._jobs[job.id] = job
        await self._queue.put(job)
        logger.info("Job %s queued", job.id)
        return job.id

    def get_job(self, job_id: str) -> Job | None:
        """Get job status."""
        return self._jobs.get(job_id)

    def list_jobs(self, status: JobStatus | None = None) -> list[Job]:
        """List jobs, optionally filtered by status."""
        jobs = list(self._jobs.values())
        if status:
            jobs = [j for j in jobs if j.status == status]
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)

    async def cancel(self, job_id: str) -> bool:
        """Cancel a queued job."""
        job = self._jobs.get(job_id)
        if job and job.status == JobStatus.QUEUED:
            job.status = JobStatus.CANCELLED
            return True
        return False

    async def start_workers(self, worker_fn) -> None:
        """Start background workers to process jobs."""
        for i in range(self._max_concurrent):
            task = asyncio.create_task(self._worker(worker_fn, i))
            self._workers.append(task)

    async def _worker(self, worker_fn, worker_id: int) -> None:
        """Worker loop that processes jobs from the queue."""
        while True:
            try:
                job = await self._queue.get()
                if job.status == JobStatus.CANCELLED:
                    self._queue.task_done()
                    continue

                async with self._semaphore:
                    job.status = JobStatus.RUNNING
                    job.started_at = datetime.now(timezone.utc).isoformat()
                    try:
                        result = await worker_fn(job)
                        job.result = result or ""
                        job.status = JobStatus.COMPLETED
                    except Exception as e:
                        job.error = str(e)
                        job.status = JobStatus.FAILED
                        logger.error("Job %s failed: %s", job.id, e)
                    finally:
                        job.completed_at = datetime.now(timezone.utc).isoformat()

                self._queue.task_done()
            except asyncio.CancelledError:
                break

    async def shutdown(self) -> None:
        """Shutdown all workers."""
        for w in self._workers:
            w.cancel()
        self._workers.clear()
