"""The base prompt's stance toward the deterministic engine is capability-gated.

Regression (G4): _BASE_PROMPT hard-coded '...narrate them. Never re-run a detector'
— the '4B narrates' framing grabbed into the live prompt, capping a capable model
at narrator of the deterministic engine."""

from __future__ import annotations

from kryon.skills.unified_agent import _BASE_PROMPT, _engine_stance


def test_engine_stance_4b_forbids_rerun(monkeypatch):
    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    stance = _engine_stance()
    assert "Never re-run" in stance
    assert "narrate them" in stance


def test_engine_stance_capable_is_head_start(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    stance = _engine_stance()
    assert "HEAD START" in stance
    assert "Never re-run" not in stance
    assert "chain PAST them" in stance


def test_base_prompt_formats_with_both_placeholders():
    # Guard: adding {engine_stance} must not break the .format() call.
    out = _BASE_PROMPT.format(skill_sections="X", engine_stance=_engine_stance())
    assert "KRYON" in out and "X" in out
