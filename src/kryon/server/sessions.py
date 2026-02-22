"""Session management for concurrent agent runs."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ServerSession:
    """A server-side session holding agent state and message history."""

    session_id: str
    agent_key: str
    agent: Any  # Agent instance
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    messages: list[dict[str, Any]] = field(default_factory=list)
    input_history: list[Any] = field(default_factory=list)


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
    events: list[dict[str, Any]] = field(default_factory=list)
    task: asyncio.Task | None = field(default=None, repr=False)


class SessionManager:
    """Manages sessions and concurrent runs."""

    def __init__(self, max_concurrent_runs: int = 10):
        self._sessions: dict[str, ServerSession] = {}
        self._runs: dict[str, RunState] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent_runs)

    # --- Sessions ---

    def create_session(self, agent_key: str, agent: Any) -> ServerSession:
        session_id = uuid.uuid4().hex[:12]
        session = ServerSession(session_id=session_id, agent_key=agent_key, agent=agent)
        self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> ServerSession | None:
        return self._sessions.get(session_id)

    def list_sessions(self) -> list[ServerSession]:
        return list(self._sessions.values())

    def delete_session(self, session_id: str) -> bool:
        return self._sessions.pop(session_id, None) is not None

    # --- Runs ---

    def create_run(self, agent_key: str, session_id: str | None = None) -> RunState:
        run_id = uuid.uuid4().hex[:12]
        run = RunState(run_id=run_id, session_id=session_id, agent_key=agent_key)
        self._runs[run_id] = run
        return run

    def get_run(self, run_id: str) -> RunState | None:
        return self._runs.get(run_id)

    def cancel_run(self, run_id: str) -> bool:
        run = self._runs.get(run_id)
        if run and run.status == "running" and run.task:
            run.task.cancel()
            run.status = "cancelled"
            return True
        return False

    @property
    def semaphore(self) -> asyncio.Semaphore:
        return self._semaphore
