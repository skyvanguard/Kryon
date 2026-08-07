"""T4-A1: the interactive-session send must not cap output collection at a
hardcoded 3s. The adaptive wait returns fast for silent commands but keeps
collecting while the buffer is still growing (up to the caller's timeout,
bounded by ``_SESSION_MAX_WAIT``)."""

from __future__ import annotations

import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.tools.common import _dispatchers
from kryon.tools.common._sessions import ACTIVE_SESSIONS


class _FakeSession:
    """Emits ``chunks`` progressively across get_new_output peeks."""

    def __init__(self, chunks: list[str]) -> None:
        self._chunks = chunks
        self._peek = 0
        self.container_id = None
        self.ctf = None
        self.workspace_dir = "/tmp"
        self.friendly_id = "S1"

    def send_input(self, command: str) -> str:
        return "sent"

    def get_new_output(self, mark_position: bool = False) -> str:
        if mark_position:
            # reset marker / final consume
            return self._chunks[-1] if self._chunks else ""
        # peek: cumulative-since-mark, grows then plateaus
        idx = min(self._peek, len(self._chunks) - 1)
        self._peek += 1
        return self._chunks[idx]


def _install(monkeypatch, session):
    monkeypatch.setitem(ACTIVE_SESSIONS, "S1", session)
    monkeypatch.setattr(_dispatchers, "_resolve_session_id", lambda sid: "S1")
    monkeypatch.setattr(_dispatchers.time, "sleep", lambda _s: None)  # instant loop
    monkeypatch.setattr(_dispatchers, "cli_print_tool_output", lambda **kw: None, raising=False)
    monkeypatch.setattr(_dispatchers, "stop_active_timer", lambda: None)
    monkeypatch.setattr(_dispatchers, "start_idle_timer", lambda: None)
    monkeypatch.setattr(_dispatchers, "_get_agent_token_info", lambda: None)


def test_streaming_output_is_captured_not_truncated(monkeypatch):
    # Buffer grows for several peeks (>3s worth at 0.5s) then plateaus.
    chunks = ["a", "ab", "abc", "abcd", "abcde", "abcde", "abcde"]
    session = _FakeSession(chunks)
    _install(monkeypatch, session)

    out = _dispatchers.run_command("whoami", session_id="S1", timeout=30)
    assert "abcde" in out


def test_silent_command_returns_fast(monkeypatch):
    # Never produces output → must not block; returns the "no output" sentinel.
    session = _FakeSession([""])
    _install(monkeypatch, session)

    out = _dispatchers.run_command("cd /tmp", session_id="S1", timeout=300)
    assert "No output captured" in out


def test_session_max_wait_caps_absolute(monkeypatch):
    # timeout=300 must NOT translate into a 300-iteration wait; capped by _SESSION_MAX_WAIT.
    assert _dispatchers._SESSION_MAX_WAIT <= 300
    # ever-growing buffer would loop forever without the cap
    session = _FakeSession([str(i) * (i + 1) for i in range(2000)])
    _install(monkeypatch, session)
    out = _dispatchers.run_command("tail -f log", session_id="S1", timeout=300)
    assert isinstance(out, str)  # returned (did not hang) thanks to absolute_cap
