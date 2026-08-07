"""Tests for the interactive shell-session tools (kryon.tools.common.session_tools)."""

import pytest

from kryon.tools.common import session_tools as mod

_TOOL_NAMES = [
    "shell_session_start",
    "shell_session_input",
    "shell_session_output",
    "shell_session_close",
    "shell_session_list",
]


@pytest.mark.unit
@pytest.mark.parametrize("name", _TOOL_NAMES)
def test_tools_are_function_tools(name):
    tool = getattr(mod, name)
    assert tool.name == name
    assert hasattr(tool, "params_json_schema")


@pytest.mark.unit
def test_list_empty(monkeypatch):
    monkeypatch.setattr(mod, "_list", lambda: [])
    assert mod.shell_session_list._raw_fn() == "No active shell sessions."


@pytest.mark.unit
def test_list_formats_sessions(monkeypatch):
    monkeypatch.setattr(
        mod,
        "_list",
        lambda: [
            {
                "friendly_id": "S1",
                "session_id": "abcd1234",
                "command": "nc -lvnp 4444",
                "running": True,
                "last_activity": "10:00:00",
            }
        ],
    )
    out = mod.shell_session_list._raw_fn()
    assert "S1" in out
    assert "nc -lvnp 4444" in out
    assert "running=True" in out


@pytest.mark.unit
def test_start_failure_passthrough(monkeypatch):
    monkeypatch.setattr(mod, "_create", lambda cmd: "Failed to start session: boom")
    out = mod.shell_session_start._raw_fn("whoami")
    assert out.startswith("Failed")


@pytest.mark.unit
def test_start_success_returns_id_and_initial_output(monkeypatch):
    monkeypatch.setattr(mod, "_create", lambda cmd: "abcd1234")
    monkeypatch.setattr(mod, "_get_output", lambda sid, clear=True: "[Session abcd1234] Started: whoami")
    out = mod.shell_session_start._raw_fn("whoami")
    assert "abcd1234" in out
    assert "Started" in out


@pytest.mark.unit
def test_input_delegates(monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(
        mod,
        "_send",
        lambda sid, data: seen.update(sid=sid, data=data) or "Input sent to session",
    )
    out = mod.shell_session_input._raw_fn("S1", "ls -la")
    assert seen == {"sid": "S1", "data": "ls -la"}
    assert "Input sent" in out


@pytest.mark.unit
def test_output_passes_clear_flag(monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(mod, "_get_output", lambda sid, clear=True: seen.update(sid=sid, clear=clear) or "buf")
    mod.shell_session_output._raw_fn("S1", clear=False)
    assert seen == {"sid": "S1", "clear": False}


@pytest.mark.unit
def test_close_delegates(monkeypatch):
    monkeypatch.setattr(mod, "_terminate", lambda sid: f"Session {sid} terminated")
    out = mod.shell_session_close._raw_fn("S1")
    assert "terminated" in out
