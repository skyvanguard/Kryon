"""`_reflection_note` — the concise WHY-label a `reflection` AgentEvent carries
so a front-end (SSE / Charm TUI) renders a one-line notice instead of the full
imperative reflection block. Pure function: precedence + formatting only."""

from __future__ import annotations

import types

from kryon.cli.reflective_runner import _reflection_note


def _note(**over):
    base = dict(
        turns_used=4,
        total_turns_cap=14,
        stuck_record=None,
        degen_pattern=None,
        stall_detected=False,
        premature_summary_detected=False,
        next_action=None,
    )
    base.update(over)
    return _reflection_note(**base)


def test_plain_cadence_is_the_fallback():
    note = _note()
    assert "reflexión de cadencia" in note
    assert "turno 4/14" in note


def test_stuck_wins_and_names_the_tool():
    rec = types.SimpleNamespace(tool_name="sqlmap")
    note = _note(stuck_record=rec)
    assert "loop detectado (sqlmap)" in note


def test_stuck_takes_precedence_over_everything_else():
    rec = types.SimpleNamespace(tool_name="nuclei")
    note = _note(
        stuck_record=rec,
        degen_pattern="aaa",
        stall_detected=True,
        premature_summary_detected=True,
        next_action=types.SimpleNamespace(tool="hydra"),
    )
    assert note.startswith("loop detectado (nuclei)")


def test_degeneracy_before_premature():
    note = _note(degen_pattern="repeat-line", premature_summary_detected=True)
    assert "repetición intra-turno" in note


def test_premature_before_stall():
    note = _note(premature_summary_detected=True, stall_detected=True)
    assert "resumen prematuro" in note


def test_stall_before_next_action():
    note = _note(stall_detected=True, next_action=types.SimpleNamespace(tool="ffuf"))
    assert "sin progreso" in note


def test_next_action_names_the_suggested_tool():
    note = _note(next_action=types.SimpleNamespace(tool="GetNPUsers.py"))
    assert "próxima acción sugerida: GetNPUsers.py" in note


def test_next_action_without_tool_falls_back_to_cadence():
    note = _note(next_action=types.SimpleNamespace(tool=""))
    assert "reflexión de cadencia" in note
