"""Tests for the SAST specialist sub-agent (as_tool delegation, Phase 1)."""

from __future__ import annotations

import pytest

from kryon.sdk.agents import function_tool


@function_tool
def _fake_run_command(command: str) -> str:
    """Stub so the specialist builds without the full tool registry."""
    return ""


def _reg() -> dict:
    return {"run_command": _fake_run_command}


@pytest.mark.unit
def test_sast_specialist_is_focused():
    from kryon.agents.specialists.sast_agent import create_sast_specialist

    agent = create_sast_specialist(_reg())
    assert agent.name == "SAST-Specialist"
    # Tight toolset: just run_command — NOT the unified agent's 15-tool budget.
    assert len(agent.tools) == 1
    assert "SAST" in agent.instructions
    assert "grep" in agent.instructions


@pytest.mark.unit
def test_sast_review_is_a_delegation_tool():
    from kryon.agents.specialists.sast_agent import sast_review_tool

    tool = sast_review_tool(_reg())
    # as_tool wraps the specialist as a callable tool the orchestrator delegates
    # to (isolated context); the orchestrator keeps the thread (not a handoff).
    assert getattr(tool, "name", None) == "sast_review"


@pytest.mark.unit
def test_subagent_gated_by_env(monkeypatch):
    """KRYON_SUBAGENTS gates whether the unified agent exposes sast_review."""
    from kryon.skills.unified_agent import create_unified_agent

    monkeypatch.delenv("KRYON_SUBAGENTS", raising=False)
    names_off = {getattr(t, "name", "") for t in create_unified_agent(user_msg="audita este código").tools}
    assert "sast_review" not in names_off

    monkeypatch.setenv("KRYON_SUBAGENTS", "true")
    names_on = {getattr(t, "name", "") for t in create_unified_agent(user_msg="audita este código").tools}
    assert "sast_review" in names_on
