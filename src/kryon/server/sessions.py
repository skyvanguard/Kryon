"""Session management for concurrent agent runs."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ServerSession:
    """A server-side session holding agent state and message history."""

    session_id: str
    agent_key: str
    agent: Any  # Agent instance (None until rebuilt for a persisted session)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    messages: list[dict[str, Any]] = field(default_factory=list)
    input_history: list[Any] = field(default_factory=list)
    # Per-session model override (#3) — None uses the server's configured model.
    model: str | None = None
    # JWT user that created the session; None in single-tenant API-key mode.
    # Used to prevent cross-user session enumeration / hijack in multi-user setups.
    owner_user_id: str | None = None

    def to_persisted(self) -> dict[str, Any]:
        """JSON-safe snapshot for disk (#2). The agent instance is NOT stored — it
        rebuilds from ``input_history`` + ``model`` on resume."""
        return {
            "session_id": self.session_id,
            "agent_key": self.agent_key,
            "created_at": self.created_at,
            "input_history": self.input_history,
            "model": self.model,
            "owner_user_id": self.owner_user_id,
        }


# Live runs stream their AgentEvents to any number of SSE readers via `events`.
# It's a bounded ring buffer: a pathological run can emit thousands of frames and
# memory must not grow without limit (× up to max_concurrent_runs). Because the
# buffer drops its oldest entries under overflow, readers must NOT index it
# positionally — they track how many frames they've consumed and ask `events_since`,
# which maps that cursor onto the live window and accounts for evicted frames.
_EVENT_BUFFER_MAXLEN = 5_000


@dataclass
class RunState:
    """Tracks state of an in-progress agent run."""

    run_id: str
    session_id: str | None
    agent_key: str
    status: str = "running"  # running | completed | failed | cancelled
    output: str = ""
    agent_name: str = ""
    usage: dict[str, Any] = field(default_factory=dict)
    events: deque = field(default_factory=lambda: deque(maxlen=_EVENT_BUFFER_MAXLEN))
    # Monotonic count of frames EVER appended (survives ring-buffer eviction). `events`
    # holds only the last `_EVENT_BUFFER_MAXLEN`; this counts all of them, so a reader
    # can tell how many were dropped before it caught up.
    total_events: int = 0
    task: asyncio.Task | None = field(default=None, repr=False)

    def append_event(self, sse: str) -> None:
        """Buffer one SSE frame for the run's stream readers."""
        self.events.append({"sse": sse})
        self.total_events += 1

    def events_since(self, served: int) -> tuple[list[str], int]:
        """Frames a reader that already consumed ``served`` events hasn't seen yet,
        plus its updated consumed-count.

        The buffer is a bounded ring holding the last ``maxlen`` frames — the absolute
        range ``[total_events - len(events), total_events)``. We map the reader's absolute
        ``served`` cursor onto that live window instead of indexing positionally (the old
        `events[idx]` mis-served the moment eviction shifted the deque, and its `idx`
        could run past a `len` capped at ``maxlen``, hanging the tail forever). If the
        reader fell so far behind that its next frame was already evicted, those frames
        are gone (a bounded buffer cannot replay them) and it resumes from the oldest
        live frame — graceful degradation, never a mis-served or skipped-forever frame.
        """
        dropped = self.total_events - len(self.events)
        start = max(served - dropped, 0)
        out = [self.events[i]["sse"] for i in range(start, len(self.events))]
        return out, self.total_events


_MAX_RUNS = 10_000
_MAX_SESSIONS = 1_000


class SessionManager:
    """Manages sessions and concurrent runs."""

    def __init__(self, max_concurrent_runs: int = 10, persist_dir: str | Path | None = None):
        self._sessions: dict[str, ServerSession] = {}
        self._runs: dict[str, RunState] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent_runs)
        # #2 persistence: one JSON per session under persist_dir; sessions survive
        # a server restart. The agent object isn't stored — it rebuilds lazily from
        # the conversation history on first access (get_session). Dir precedence:
        # explicit arg > KRYON_SESSION_DIR env (lets tests/CI isolate) > ~/.kryon/sessions.
        import os

        self._persist_dir = Path(
            persist_dir or os.environ.get("KRYON_SESSION_DIR") or (Path.home() / ".kryon" / "sessions")
        )
        # Opt-out entirely (persistence off) with KRYON_SESSION_PERSIST=false.
        self._persist_enabled = os.environ.get("KRYON_SESSION_PERSIST", "true").strip().lower() != "false"
        if self._persist_enabled:
            self._load_persisted()

    # --- Sessions ---

    def create_session(
        self, agent_key: str, agent: Any, owner_user_id: str | None = None, model: str | None = None
    ) -> ServerSession:
        session_id = uuid.uuid4().hex[:12]
        session = ServerSession(
            session_id=session_id, agent_key=agent_key, agent=agent, owner_user_id=owner_user_id, model=model
        )
        # Evict oldest session if at capacity — from memory AND disk, so the on-disk
        # set stays bounded. Without the disk delete, evicted sessions linger as files
        # and get re-loaded on every restart, growing the dir without limit.
        while len(self._sessions) >= _MAX_SESSIONS:
            oldest_id = next(iter(self._sessions))
            self._sessions.pop(oldest_id)
            self._delete_persisted_file(oldest_id)
        self._sessions[session_id] = session
        self.persist_session(session)
        return session

    def get_session(self, session_id: str) -> ServerSession | None:
        s = self._sessions.get(session_id)
        if s is not None and s.agent is None:
            # Persisted session loaded from disk — rebuild its agent + restore the
            # conversation so it REMEMBERS where it left off (#2 resume).
            self._rebuild_agent(s)
        return s

    def list_sessions(self) -> list[ServerSession]:
        return list(self._sessions.values())

    def delete_session(self, session_id: str) -> bool:
        removed = self._sessions.pop(session_id, None) is not None
        self._delete_persisted_file(session_id)
        return removed

    def _delete_persisted_file(self, session_id: str) -> None:
        """Remove a session's on-disk snapshot (best-effort)."""
        try:
            (self._persist_dir / f"{session_id}.json").unlink(missing_ok=True)
        except Exception as e:  # noqa: BLE001
            logger.debug("session file delete failed: %s", e)

    # --- #2 persistence ---

    def persist_session(self, session: ServerSession) -> None:
        """Write the session's conversation snapshot to disk (best-effort)."""
        if not self._persist_enabled:
            return
        try:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            path = self._persist_dir / f"{session.session_id}.json"
            path.write_text(json.dumps(session.to_persisted(), ensure_ascii=False), encoding="utf-8")
        except Exception as e:  # noqa: BLE001 — persistence must never break a run
            logger.debug("session persist failed: %s", e)

    def _load_persisted(self) -> None:
        """Load persisted sessions on startup (agent left None → rebuilt on access).

        Bounded: keep only the most-recent ``_MAX_SESSIONS`` snapshots (by mtime) and
        prune the older files, so a long-lived appliance's session dir can't grow
        without limit or slow startup by loading tens of thousands of stale files."""
        try:
            if not self._persist_dir.exists():
                return

            def _mtime(p: Path) -> float:
                try:
                    return p.stat().st_mtime
                except OSError:
                    return 0.0

            files = sorted(self._persist_dir.glob("*.json"), key=_mtime)  # oldest first
            if len(files) > _MAX_SESSIONS:
                # Prune the oldest overflow from disk; keep the newest _MAX_SESSIONS.
                for stale in files[:-_MAX_SESSIONS]:
                    try:
                        stale.unlink(missing_ok=True)
                    except OSError as e:
                        logger.debug("prune stale session file failed: %s", e)
                files = files[-_MAX_SESSIONS:]

            # Load oldest-first so dict insertion order reflects age → later eviction
            # in create_session drops the genuinely-oldest session.
            for f in files:
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    sid = data.get("session_id")
                    if not sid:
                        continue
                    self._sessions[sid] = ServerSession(
                        session_id=sid,
                        agent_key=data.get("agent_key", "kryon"),
                        agent=None,  # rebuilt lazily
                        created_at=data.get("created_at") or datetime.now(timezone.utc).isoformat(),
                        input_history=data.get("input_history", []) or [],
                        model=data.get("model"),
                        owner_user_id=data.get("owner_user_id"),
                    )
                except Exception as e:  # noqa: BLE001
                    logger.debug("session load failed for %s: %s", f, e)
        except Exception as e:  # noqa: BLE001
            logger.debug("session dir scan failed: %s", e)

    def _rebuild_agent(self, session: ServerSession) -> None:
        """Rebuild a persisted session's agent and restore its conversation."""
        try:
            from kryon.agents import get_agent_by_name

            agent = get_agent_by_name(session.agent_key, model_override=session.model)
            model = getattr(agent, "model", None)
            if model is not None and session.input_history and hasattr(model, "message_history"):
                model.message_history = list(session.input_history)  # agent REMEMBERS
            session.agent = agent
        except Exception as e:  # noqa: BLE001
            logger.warning("session agent rebuild failed for %s: %s", session.session_id, e)

    # --- Runs ---

    def create_run(self, agent_key: str, session_id: str | None = None) -> RunState:
        run_id = uuid.uuid4().hex[:12]
        run = RunState(run_id=run_id, session_id=session_id, agent_key=agent_key)
        # Evict completed/failed runs if at capacity
        if len(self._runs) >= _MAX_RUNS:
            to_remove = [rid for rid, r in self._runs.items() if r.status in ("completed", "failed", "cancelled")]
            for rid in to_remove[:100]:
                del self._runs[rid]
        self._runs[run_id] = run
        return run

    def get_run(self, run_id: str) -> RunState | None:
        return self._runs.get(run_id)

    def cancel_run(self, run_id: str) -> bool:
        run = self._runs.get(run_id)
        # "pending_stream" is the state a streaming run sits in for its whole life
        # (it only flips to completed/failed at the end) — without it here, a
        # streamed run (the TUI's rich_events path included) could never be
        # cancelled, so a Ctrl+C'd turn kept running headless.
        if run and run.status in ("running", "pending_stream") and run.task:
            run.task.cancel()
            run.status = "cancelled"
            return True
        return False

    @property
    def semaphore(self) -> asyncio.Semaphore:
        return self._semaphore
