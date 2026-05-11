"""
Supervisor tools for the planner_hunter coordinator.

Ported from ARTEMIS (arXiv 2512.09882) supervisor API. The planner agent
uses these to spawn/control a bounded pool of hunter sub-agents, keep
cross-run notes, and maintain a recursive TODO list — the three mechanisms
that extended ARTEMIS's horizon from <2h to 16h+.

VRAM constraint (12 GB) shapes the design:
  - HunterPool caps active hunters at KRYON_HUNTER_PARALLELISM (default 2).
  - Ollama serializes inference per model, so "parallel" here means
    overlapped tool execution (git ops, ASAN compiles, I/O) while only
    one hunter holds the model at a time.
  - Pending spawns queue FIFO until a slot frees.

The actual hunter invocation is injected via `register_hunter_runner()`
to keep this module testable with mock runners.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from kryon.sdk.agents import function_tool

logger = logging.getLogger(__name__)

_MAX_PARALLEL = int(os.environ.get("KRYON_HUNTER_PARALLELISM", "2"))
# F5.1.a — lift artificial constraints. Mythos/ARTEMIS agents run for
# hours with hundreds of turns; 15 min was my own overcorrection.
_HUNTER_TIMEOUT_S = int(os.environ.get("KRYON_HUNTER_TIMEOUT_S", "1800"))  # 30 min

# Supervisor-visible caps so prompts stay small
_MAX_NOTES = 20
_MAX_NOTE_CHARS = 2000
_MAX_TODOS = 30


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class HunterJob:
    """State for a single hunter sub-agent."""

    hunter_id: str
    file_path: str
    hypothesis_hint: str = ""
    cwe_candidate: str = ""
    parent_cve: str = ""
    prompt: str = ""  # filled by dynamic_prompt.generate_hunter_prompt
    started_at: float = 0.0
    finished_at: float = 0.0
    status: str = "pending"  # pending | running | finished | terminated | failed
    findings: list[dict] = field(default_factory=list)
    error: str = ""
    followups: list[str] = field(default_factory=list)

    def duration_s(self) -> float:
        if self.finished_at:
            return self.finished_at - self.started_at
        if self.started_at:
            return time.time() - self.started_at
        return 0.0

    def summary(self) -> dict:
        return {
            "hunter_id": self.hunter_id,
            "file": self.file_path,
            "status": self.status,
            "duration_s": round(self.duration_s(), 1),
            "findings_count": len(self.findings),
            "cwe_candidate": self.cwe_candidate,
            "error": self.error[:200] if self.error else "",
        }


# The signature a hunter runner must satisfy. Returns a list of findings
# (dicts; shape decided by the hunter playbook / zero-day-hunter).
HunterRunner = Callable[[HunterJob], Awaitable[list[dict]]]


# ---------------------------------------------------------------------------
# HunterPool — bounded concurrent execution
# ---------------------------------------------------------------------------


class HunterPool:
    """Asyncio-based bounded pool for hunter sub-agents.

    Lifecycle:
        pool = HunterPool(max_active=2, runner=my_runner)
        hid = await pool.spawn(job)       # returns hunter_id; may queue
        ... planner does other work ...
        result = await pool.await_result(hid)   # blocks until finished
        await pool.shutdown()
    """

    def __init__(
        self,
        max_active: int = _MAX_PARALLEL,
        runner: HunterRunner | None = None,
        default_timeout_s: int = _HUNTER_TIMEOUT_S,
    ):
        self.max_active = max_active
        self.runner = runner
        self.default_timeout_s = default_timeout_s

        self._jobs: dict[str, HunterJob] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._sem = asyncio.Semaphore(max_active)
        self._done_events: dict[str, asyncio.Event] = {}

    def set_runner(self, runner: HunterRunner) -> None:
        """Inject the real hunter runner (deferred to avoid import cycles)."""
        self.runner = runner

    async def spawn(self, job: HunterJob) -> str:
        """Register a new hunter; it runs as soon as a slot frees."""
        if self.runner is None:
            raise RuntimeError(
                "HunterPool has no runner. Call set_runner() or pass one to __init__."
            )
        if not job.hunter_id:
            job.hunter_id = f"h_{uuid.uuid4().hex[:10]}"
        self._jobs[job.hunter_id] = job
        self._done_events[job.hunter_id] = asyncio.Event()
        self._tasks[job.hunter_id] = asyncio.create_task(self._run_one(job))
        return job.hunter_id

    async def _run_one(self, job: HunterJob) -> None:
        """Slot acquire → runner → record outcome → release."""
        async with self._sem:
            job.status = "running"
            job.started_at = time.time()
            try:
                findings = await asyncio.wait_for(
                    self.runner(job), timeout=self.default_timeout_s
                )
                job.findings = findings or []
                job.status = "finished"
                logger.info(
                    "hunter %s FINISHED: %d findings in %.1fs",
                    job.hunter_id, len(job.findings), job.duration_s(),
                )
            except asyncio.CancelledError:
                job.status = "terminated"
                raise
            except asyncio.TimeoutError:
                job.status = "failed"
                job.error = f"timeout after {self.default_timeout_s}s"
                logger.warning("hunter %s TIMEOUT", job.hunter_id)
            except Exception as e:
                job.status = "failed"
                job.error = str(e)[:500]
                logger.exception("hunter %s raised: %s", job.hunter_id, e)
            finally:
                job.finished_at = time.time()
                self._done_events[job.hunter_id].set()

    async def await_result(self, hunter_id: str) -> HunterJob:
        """Block until the specified hunter finishes (or fails/terminates)."""
        evt = self._done_events.get(hunter_id)
        if evt is None:
            raise KeyError(hunter_id)
        await evt.wait()
        return self._jobs[hunter_id]

    async def await_all(self) -> list[HunterJob]:
        """Wait for every spawned hunter; return all jobs in finish order."""
        if not self._done_events:
            return []
        await asyncio.gather(*(e.wait() for e in self._done_events.values()))
        return list(self._jobs.values())

    async def terminate(self, hunter_id: str, reason: str = "") -> bool:
        """Cancel a running hunter."""
        task = self._tasks.get(hunter_id)
        if task is None or task.done():
            return False
        task.cancel()
        job = self._jobs[hunter_id]
        job.status = "terminated"
        job.error = f"terminated: {reason}" if reason else "terminated"
        self._done_events[hunter_id].set()
        return True

    def get(self, hunter_id: str) -> HunterJob | None:
        return self._jobs.get(hunter_id)

    def list_active(self) -> list[HunterJob]:
        """Return hunters currently executing (inside the semaphore).

        Hunters in the queue waiting for a slot have status == "pending" and
        are returned by `list_queued()` instead.
        """
        return [j for j in self._jobs.values() if j.status == "running"]

    def list_queued(self) -> list[HunterJob]:
        return [j for j in self._jobs.values() if j.status == "pending"]

    def list_all(self) -> list[HunterJob]:
        return list(self._jobs.values())

    def send_followup(self, hunter_id: str, nudge: str) -> bool:
        """Queue a follow-up instruction the hunter can read on its next turn.

        The hunter runner is responsible for consuming `job.followups`.
        """
        job = self._jobs.get(hunter_id)
        if job is None or job.status not in ("pending", "running"):
            return False
        job.followups.append(nudge[:1000])
        return True

    async def shutdown(self) -> None:
        """Cancel all active tasks; wait for cleanup."""
        for tid, task in list(self._tasks.items()):
            if not task.done():
                task.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)


# ---------------------------------------------------------------------------
# Singleton pool + supervisor notes/TODO state
# ---------------------------------------------------------------------------


class SupervisorState:
    """Mutable key-value notes + TODO list, exposed via tools below."""

    def __init__(self) -> None:
        self.notes: dict[str, str] = {}
        self.todos: list[dict] = []

    def write_note(self, key: str, content: str) -> None:
        if len(self.notes) >= _MAX_NOTES and key not in self.notes:
            # evict oldest
            oldest = next(iter(self.notes))
            self.notes.pop(oldest)
        self.notes[key] = content[:_MAX_NOTE_CHARS]

    def read_notes(self) -> dict[str, str]:
        return dict(self.notes)

    def update_todos(self, todos: list[dict]) -> None:
        self.todos = list(todos)[:_MAX_TODOS]

    def read_todos(self) -> list[dict]:
        return list(self.todos)

    def reset(self) -> None:
        self.notes.clear()
        self.todos.clear()


_pool: HunterPool | None = None
_state: SupervisorState = SupervisorState()


def get_pool() -> HunterPool:
    global _pool
    if _pool is None:
        _pool = HunterPool()
    return _pool


def set_pool(pool: HunterPool) -> None:
    """Test/runtime-injectable pool override."""
    global _pool
    _pool = pool


def get_state() -> SupervisorState:
    return _state


def reset_supervisor() -> None:
    """Clear pool + notes + todos. Called on /flush."""
    global _pool
    if _pool is not None:
        # best-effort cancel; we're in a sync path so can't await
        for tid, t in list(_pool._tasks.items()):
            if not t.done():
                t.cancel()
    _pool = None
    _state.reset()


# ---------------------------------------------------------------------------
# @function_tool wrappers — what the planner agent actually calls
# ---------------------------------------------------------------------------


@function_tool(strict_mode=False)
def spawn_hunter(
    file_path: str,
    hypothesis_hint: str = "",
    cwe_candidate: str = "",
    parent_cve: str = "",
) -> str:
    """Register a new hunter sub-agent to investigate `file_path`.

    Returns JSON with {hunter_id, queued, pool_active, pool_max}.
    The hunter runs as soon as a pool slot frees; the planner can
    poll via read_supervisor_notes or await via CLI.

    Args:
        file_path: Absolute path to the source file to hunt in.
        hypothesis_hint: Optional one-line suggestion (e.g. "heap OOB in parse_header").
        cwe_candidate: Optional CWE id (e.g. "CWE-787") to guide the hunter.
        parent_cve: Optional CVE this hunt derives from (variant analysis).
    """
    pool = get_pool()
    job = HunterJob(
        hunter_id="",
        file_path=file_path,
        hypothesis_hint=hypothesis_hint,
        cwe_candidate=cwe_candidate,
        parent_cve=parent_cve,
    )
    try:
        # If we're already inside a running loop, schedule; otherwise run.
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Schedule as a task; the tool returns immediately
            loop.create_task(pool.spawn(job))
            # Assign a provisional ID so the planner can refer to it
            if not job.hunter_id:
                job.hunter_id = f"h_{uuid.uuid4().hex[:10]}"
        else:
            asyncio.run(pool.spawn(job))
    except RuntimeError:
        # no event loop → run sync
        asyncio.run(pool.spawn(job))

    return json.dumps({
        "hunter_id": job.hunter_id,
        "file": file_path,
        "pool_active": len(pool.list_active()),
        "pool_max": pool.max_active,
    })


@function_tool(strict_mode=False)
def terminate_hunter(hunter_id: str, reason: str = "") -> str:
    """Cancel a running hunter.

    Returns JSON with {hunter_id, terminated: bool, status}.
    """
    pool = get_pool()
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            task = loop.create_task(pool.terminate(hunter_id, reason))
            # fire-and-forget: the cancellation propagates
            terminated = True
        else:
            terminated = asyncio.run(pool.terminate(hunter_id, reason))
    except RuntimeError:
        terminated = asyncio.run(pool.terminate(hunter_id, reason))

    job = pool.get(hunter_id)
    return json.dumps({
        "hunter_id": hunter_id,
        "terminated": terminated,
        "status": job.status if job else "unknown",
    })


@function_tool(strict_mode=False)
def send_followup(hunter_id: str, nudge: str) -> str:
    """Queue a follow-up instruction for a running hunter.

    The hunter sees it on its next turn. Use for steering mid-flight
    ("also check the length parameter", "ignore the false positive in X").

    Returns JSON with {hunter_id, queued: bool}.
    """
    queued = get_pool().send_followup(hunter_id, nudge)
    return json.dumps({"hunter_id": hunter_id, "queued": queued})


@function_tool(strict_mode=False)
def write_supervisor_note(key: str, content: str) -> str:
    """Persist a key→content note for the planner across turns.

    Use sparingly — max {max_notes} notes, {max_chars} chars each.
    """
    get_state().write_note(key, content)
    return json.dumps({"key": key, "saved": True, "notes_total": len(get_state().notes)})


@function_tool(strict_mode=False)
def read_supervisor_notes() -> str:
    """Return all notes the planner has written so far."""
    return json.dumps(get_state().read_notes(), indent=2)


@function_tool(strict_mode=False)
def update_supervisor_todo(todos_json: str) -> str:
    """Replace the TODO list. Input is a JSON array of {file, priority, status}."""
    try:
        todos = json.loads(todos_json) if isinstance(todos_json, str) else todos_json
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(todos, list):
        return json.dumps({"error": "expected a JSON array"})
    get_state().update_todos(todos)
    return json.dumps({"saved": True, "count": len(get_state().todos)})


@function_tool(strict_mode=False)
def read_supervisor_todo() -> str:
    """Return the planner's current TODO list."""
    return json.dumps(get_state().read_todos(), indent=2)


@function_tool(strict_mode=False)
def list_hunters() -> str:
    """Return a summary of all hunters (pending, running, finished, failed)."""
    pool = get_pool()
    return json.dumps({
        "pool_max": pool.max_active,
        "active": len(pool.list_active()),
        "hunters": [j.summary() for j in pool.list_all()],
    }, indent=2)
