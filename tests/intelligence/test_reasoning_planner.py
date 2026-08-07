"""Tests for the reasoning-driven next-action planner (gated, injectable model)."""

from __future__ import annotations

from kryon.intelligence.attack_graph import AttackGraph, Capability
from kryon.intelligence.exploit_chain_planner import NextActionRecommendation
from kryon.intelligence.reasoning_planner import (
    _build_prompt,
    plan_hybrid,
    propose_next_action,
    summarize_findings,
)

_GOOD = '{"tool": "jwt_forge", "args": "--secret k <target>", "rationale": "use leaked secret", "confidence": 0.9}'


def _graph() -> AttackGraph:
    g = AttackGraph()
    g.add_edge(None, Capability("secret", "k", "h"), "leak")
    return g


def _model(_prompt: str) -> str:
    return "Here is the plan:\n" + _GOOD


def test_capable_model_proposes_parsed_action():
    rec = propose_next_action(_graph(), "secret k found", [], _model, enabled=True)
    assert rec is not None
    assert rec.tool == "jwt_forge"
    assert rec.confidence == 0.9
    assert "<target>" in rec.args


def test_disabled_returns_none():
    assert propose_next_action(_graph(), "x", [], _model, enabled=False) is None


def test_no_model_returns_none():
    assert propose_next_action(_graph(), "x", [], None, enabled=True) is None


def test_model_declines_returns_none():
    assert propose_next_action(_graph(), "x", [], lambda p: "NONE", enabled=True) is None


def test_unparseable_returns_none():
    assert propose_next_action(_graph(), "x", [], lambda p: "no json here at all", enabled=True) is None


def test_model_error_returns_none():
    def boom(_):
        raise RuntimeError("model down")

    assert propose_next_action(_graph(), "x", [], boom, enabled=True) is None


class _F:
    def __init__(self, cwe, title, host):
        self.cwe = cwe
        self.title = title
        self.affected_asset = host


def test_summarize_findings_chains_from_weaknesses():
    s = summarize_findings([_F("CWE-89", "SQLi in q", "juice:3000"), _F("CWE-639", "IDOR Users", "juice:3000")])
    assert "CWE-89" in s and "SQLi" in s and "juice:3000" in s
    assert "CWE-639" in s
    assert summarize_findings([]) == ""


def test_build_prompt_includes_findings_when_present():
    p = _build_prompt("state", "facts", [], "CWE-89 SQLi @ h")
    assert "CHAIN FROM THESE" in p
    assert "CWE-89 SQLi @ h" in p
    # Absent when no findings.
    assert "CHAIN FROM THESE" not in _build_prompt("state", "facts", [])


def test_plan_hybrid_reasoning_first_then_rules_fallback():
    def rules():
        return NextActionRecommendation(tool="rules_tool", args="", rationale="from rules")

    # No model -> falls back to rules.
    r = plan_hybrid(_graph(), "x", [], model_caller=None, rules_fallback=rules, enabled=True)
    assert r.tool == "rules_tool"

    # Capable model present -> reasoning wins.
    r2 = plan_hybrid(_graph(), "x", [], model_caller=_model, rules_fallback=rules, enabled=True)
    assert r2.tool == "jwt_forge"

    # Disabled -> rules even with a model present.
    r3 = plan_hybrid(_graph(), "x", [], model_caller=_model, rules_fallback=rules, enabled=False)
    assert r3.tool == "rules_tool"
