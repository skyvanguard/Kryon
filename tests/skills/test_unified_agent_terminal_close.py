"""The deterministic terminal-close must NOT fire for a capable model.

Regression (T3-A1): run_web_pentest terminal-closed the turn unconditionally, cutting
a capable model off at the foothold (it couldn't chain dump→creds→SSH). The close
exists only to skip the 4B's slow narration turn."""

from __future__ import annotations

from types import SimpleNamespace

from kryon.skills.unified_agent import _deterministic_terminal_close


def _tr(name: str, output: str = '{"summary": {}, "findings": []}'):
    return SimpleNamespace(tool=SimpleNamespace(name=name), output=output)


def test_terminal_close_fires_for_4b(monkeypatch):
    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    res = _deterministic_terminal_close(None, [_tr("run_web_pentest")])
    assert res.is_final_output is True


def test_terminal_close_skipped_for_capable_model(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    res = _deterministic_terminal_close(None, [_tr("run_web_pentest")])
    assert res.is_final_output is False  # capable model keeps chaining


def test_non_terminal_tool_never_closes(monkeypatch):
    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    res = _deterministic_terminal_close(None, [_tr("run_command")])
    assert res.is_final_output is False
