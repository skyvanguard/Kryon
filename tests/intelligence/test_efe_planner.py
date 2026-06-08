"""F5 — tests for symbolic Expected-Free-Energy action selection.

Key invariant: with the feature OFF (default) or with epistemic weight 0,
``plan_next_action`` behaves exactly like the legacy first-match-wins — so the
~70 existing chain-planner tests are untouched.
"""

from __future__ import annotations

from kryon.intelligence.exploit_chain_planner import (
    NextActionRecommendation,
    _efe_enabled,
    _efe_score,
    _efe_weight,
    _epistemic_gain,
    plan_next_action,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

# --- epistemic gain (pure) -------------------------------------------------


def test_gain_high_when_field_empty():
    """An action that enumerates users, when we have none, opens new ground."""
    rec = NextActionRecommendation(tool="run_command", args="GetNPUsers.py -no-pass thm.local/", rationale="")
    assert _epistemic_gain(ExtractedFacts(), rec) == 1.0


def test_gain_low_when_field_known():
    """A users-only action when we already have users → little new info.
    (enum4linux -U hits only the 'users' signal, not hashes.)"""
    rec = NextActionRecommendation(tool="run_command", args="enum4linux -U 10.0.0.1", rationale="")
    facts = ExtractedFacts(users=("admin", "svc"))
    assert _epistemic_gain(facts, rec) == 0.2


def test_gain_zero_when_no_signal():
    rec = NextActionRecommendation(tool="web_fetch_smart", args="https://x/", rationale="")
    assert _epistemic_gain(ExtractedFacts(), rec) == 0.0


# --- efe score: order dominates at w=0 -------------------------------------


def test_efe_score_order_dominates_at_w0():
    """At w=0, an earlier rule (lower index) always outscores a later one,
    regardless of epistemic gain → preserves first-match precedence."""
    rec = NextActionRecommendation(tool="t", args="GetNPUsers", rationale="", confidence=0.8)
    early = _efe_score(rec, rule_index=0, n_rules=24, facts=ExtractedFacts(), w=0.0)
    late = _efe_score(rec, rule_index=5, n_rules=24, facts=ExtractedFacts(), w=0.0)
    assert early > late


def test_efe_score_epistemic_can_flip_close_candidates():
    """With w high enough, epistemic gain flips two near-adjacent candidates."""
    rec_newground = NextActionRecommendation(tool="t", args="GetNPUsers", rationale="", confidence=0.8)
    rec_known = NextActionRecommendation(tool="t", args="whoami", rationale="", confidence=0.8)
    empty = ExtractedFacts()
    # rec_known is "earlier" (index 0) but no info gain; rec_newground later (index 1) but gain=1.0
    s_known = _efe_score(rec_known, rule_index=0, n_rules=24, facts=empty, w=5.0)
    s_newground = _efe_score(rec_newground, rule_index=1, n_rules=24, facts=empty, w=5.0)
    assert s_newground > s_known


# --- env gating ------------------------------------------------------------


def test_efe_disabled_by_default(monkeypatch):
    monkeypatch.delenv("KRYON_EFE_PLANNER", raising=False)
    assert _efe_enabled() is False


def test_efe_weight_parse(monkeypatch):
    monkeypatch.setenv("KRYON_EFE_EPISTEMIC_WEIGHT", "2.5")
    assert _efe_weight() == 2.5
    monkeypatch.setenv("KRYON_EFE_EPISTEMIC_WEIGHT", "garbage")
    assert _efe_weight() == 0.0


# --- integration: OFF and on-w0 yield the same winner ----------------------


def _asrep_facts() -> ExtractedFacts:
    """Facts that fire at least one rule (AS-REP roast: users + domain, no hashes)."""
    return ExtractedFacts(users=("svc-account",), domains=("thm.local",))


def test_off_path_returns_a_recommendation(monkeypatch):
    monkeypatch.delenv("KRYON_EFE_PLANNER", raising=False)
    assert plan_next_action(_asrep_facts(), []) is not None


def test_on_w0_matches_first_match(monkeypatch):
    facts = _asrep_facts()
    monkeypatch.delenv("KRYON_EFE_PLANNER", raising=False)
    off = plan_next_action(facts, [])
    monkeypatch.setenv("KRYON_EFE_PLANNER", "true")
    monkeypatch.setenv("KRYON_EFE_EPISTEMIC_WEIGHT", "0")
    on = plan_next_action(facts, [])
    assert off is not None and on is not None
    assert (off.tool, off.args) == (on.tool, on.args)
