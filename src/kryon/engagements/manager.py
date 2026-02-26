"""Engagement manager — orchestrates multi-day autonomous engagements."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

from kryon.engagements.executor import execute_phase

__all__ = ["EngagementManager"]
from kryon.engagements.models import (
    Engagement,
    EngagementStatus,
    PhaseStatus,
)
from kryon.engagements.planner import create_phases_from_plan, generate_engagement_plan
from kryon.memory.store import MemoryStore


class EngagementManager:
    """Orchestrates multi-day pentesting engagements."""

    _SSE_QUEUE_MAXSIZE = 200

    def __init__(self, store: MemoryStore | None = None):
        self._store = store or MemoryStore()
        self._active_tasks: dict[str, asyncio.Task] = {}
        self._progress_queues: dict[str, asyncio.Queue] = {}
        self._resume_events: dict[str, asyncio.Event] = {}
        self._rate_limiter = None

    @property
    def store(self) -> MemoryStore:
        return self._store

    def cancel_all_tasks(self):
        """Cancel all active engagement tasks."""
        for task in self._active_tasks.values():
            task.cancel()
        self._active_tasks.clear()

    def _get_rate_limiter(self):
        if self._rate_limiter is None:
            try:
                from kryon.providers.rate_limiter import RateLimiter
                self._rate_limiter = RateLimiter.detect_provider()
            except Exception:
                pass
        return self._rate_limiter

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def create_engagement(self, engagement: Engagement) -> Engagement:
        """Create engagement in DB and launch execution in background."""
        self._store.create_engagement(engagement)
        task = asyncio.create_task(self._run_engagement(engagement.id))
        self._active_tasks[engagement.id] = task
        return engagement

    async def pause_engagement(self, engagement_id: str):
        """Pause an active engagement. The execution loop will detect and wait."""
        now = datetime.now(timezone.utc).isoformat()
        self._store.update_engagement(
            engagement_id, status=EngagementStatus.PAUSED.value, paused_at=now
        )
        self._emit_event(engagement_id, "paused", {"engagement_id": engagement_id})

    async def resume_engagement(self, engagement_id: str):
        """Resume a paused engagement."""
        self._store.update_engagement(
            engagement_id, status=EngagementStatus.ACTIVE.value, paused_at=None
        )

        # Wake up the waiting loop
        if engagement_id in self._resume_events:
            self._resume_events[engagement_id].set()

        # If task died (e.g. server restart), relaunch
        if engagement_id not in self._active_tasks or self._active_tasks[engagement_id].done():
            task = asyncio.create_task(self._run_engagement(engagement_id))
            self._active_tasks[engagement_id] = task

        self._emit_event(engagement_id, "resumed", {"engagement_id": engagement_id})

    async def cancel_engagement(self, engagement_id: str):
        """Cancel an engagement."""
        if engagement_id in self._active_tasks:
            self._active_tasks[engagement_id].cancel()
        self._store.update_engagement(
            engagement_id, status=EngagementStatus.CANCELLED.value
        )
        self._emit_event(engagement_id, "done", {"status": "cancelled"})

    # ------------------------------------------------------------------
    # Resume on startup
    # ------------------------------------------------------------------

    async def resume_active_engagements(self):
        """Called from app lifespan to resume engagements from DB."""
        active = self._store.list_engagements(status_filter=["active", "planning"])
        for eng in active:
            if eng.id not in self._active_tasks:
                # Reset any interrupted running phases to pending
                phases = self._store.get_engagement_phases(eng.id)
                for phase in phases:
                    if phase.status == PhaseStatus.RUNNING:
                        self._store.update_engagement_phase(
                            phase.id, status="pending", progress=0.0
                        )

                task = asyncio.create_task(self._run_engagement(eng.id))
                self._active_tasks[eng.id] = task
                logger.info("Resumed engagement %s (%s)", eng.id, eng.client_name)

    # ------------------------------------------------------------------
    # Main execution loop
    # ------------------------------------------------------------------

    async def _run_engagement(self, engagement_id: str):
        """Main engagement execution loop."""
        try:
            eng = self._store.get_engagement(engagement_id)
            if eng is None:
                return

            # --- Phase 1: Planning ---
            self._store.update_engagement(engagement_id, status=EngagementStatus.PLANNING.value)
            self._emit_event(engagement_id, "status", {"status": "planning"})

            plan = await generate_engagement_plan(eng, self._get_rate_limiter())
            phases = create_phases_from_plan(eng, plan)
            for phase in phases:
                self._store.create_engagement_phase(phase)
            self._store.update_engagement(
                engagement_id, plan_json=json.dumps(plan, default=str)
            )

            self._emit_event(engagement_id, "plan_ready", {
                "plan": plan,
                "phase_count": len(phases),
            })

            # --- Phase 2: Execute phases sequentially ---
            now = datetime.now(timezone.utc).isoformat()
            self._store.update_engagement(
                engagement_id, status=EngagementStatus.ACTIVE.value, started_at=now
            )
            self._emit_event(engagement_id, "status", {"status": "active"})

            db_phases = self._store.get_engagement_phases(engagement_id)
            for i, phase in enumerate(db_phases):
                # Check if paused
                eng = self._store.get_engagement(engagement_id)
                if eng.status == EngagementStatus.PAUSED:
                    await self._wait_for_resume(engagement_id)

                # Check if cancelled
                eng = self._store.get_engagement(engagement_id)
                if eng.status == EngagementStatus.CANCELLED:
                    return

                # Skip already completed/skipped phases
                if phase.status in (PhaseStatus.COMPLETED, PhaseStatus.SKIPPED):
                    continue

                # Execute phase
                self._emit_event(engagement_id, "log", {
                    "message": f"Starting phase {i + 1}/{len(db_phases)}: {phase.phase_type.value} (Day {phase.day_number})"
                })

                await execute_phase(
                    phase=phase,
                    engagement=eng,
                    store=self._store,
                    rate_limiter=self._get_rate_limiter(),
                    emit_event=lambda evt, data: self._emit_event(engagement_id, evt, data),
                )

                # Interval between phases (except after last one)
                if i < len(db_phases) - 1:
                    eng = self._store.get_engagement(engagement_id)
                    interval = eng.phase_interval_minutes * 60
                    if interval > 0:
                        self._emit_event(engagement_id, "log", {
                            "message": f"Waiting {eng.phase_interval_minutes}min before next phase..."
                        })
                        await asyncio.sleep(interval)

            # --- Completed ---
            now = datetime.now(timezone.utc).isoformat()
            self._store.update_engagement(
                engagement_id,
                status=EngagementStatus.COMPLETED.value,
                completed_at=now,
            )
            self._emit_event(engagement_id, "done", {"status": "completed"})

        except asyncio.CancelledError:
            self._store.update_engagement(
                engagement_id, status=EngagementStatus.CANCELLED.value
            )
        except Exception as exc:
            self._store.update_engagement(
                engagement_id,
                status=EngagementStatus.FAILED.value,
                error=str(exc),
            )
            self._emit_event(engagement_id, "done", {"status": "failed", "error": str(exc)})
        finally:
            self._active_tasks.pop(engagement_id, None)

    async def _wait_for_resume(self, engagement_id: str):
        """Wait until resume_engagement() is called."""
        if engagement_id not in self._resume_events:
            self._resume_events[engagement_id] = asyncio.Event()

        event = self._resume_events[engagement_id]
        event.clear()
        await event.wait()

    # ------------------------------------------------------------------
    # SSE support
    # ------------------------------------------------------------------

    def get_progress_queue(self, engagement_id: str) -> asyncio.Queue:
        if engagement_id not in self._progress_queues:
            self._progress_queues[engagement_id] = asyncio.Queue(maxsize=self._SSE_QUEUE_MAXSIZE)
        return self._progress_queues[engagement_id]

    def _emit_event(self, engagement_id: str, event_type: str, data: dict):
        queue = self._progress_queues.get(engagement_id)
        if queue and not queue.full():
            try:
                queue.put_nowait({"event": event_type, "data": data})
            except asyncio.QueueFull:
                pass
