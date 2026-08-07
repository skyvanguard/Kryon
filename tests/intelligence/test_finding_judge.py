"""Tests for the finding-judge (model adjudication of `inferred` findings)."""

from __future__ import annotations

from kryon.cli.engage import make_finding
from kryon.intelligence.finding_judge import JUDGE_CONFIRMED_LEVEL, _verdict_of, adjudicate_inferred


def _finding(level: str, cwe: str = "CWE-89"):
    f = make_finding(cwe=cwe, severity="HIGH", host="t", rule_id="r", message="m", evidence="ev")
    f.verification_level = level
    f.needs_verification = level in {"inferred", "heuristic"}
    return f


def test_verdict_parser():
    assert _verdict_of("REAL — clearly exploitable") == "real"
    assert _verdict_of("FALSE positive, generic banner") == "false"
    assert _verdict_of("hard to say") == "ambiguous"


def test_verdict_parser_reasoning_model_robustness():
    # leading token wins (prompt asks verdict first)
    assert _verdict_of("REAL — Apache 2.4.49 is exactly vulnerable") == "real"
    # verbose reasoning that concludes REAL with no FALSE anywhere → real
    assert _verdict_of("The banner matches and the CVE affects this exact build, so REAL.") == "real"
    # any FALSE mention is conservative → not a promotion ("not real" never promotes)
    assert _verdict_of("This is NOT real, it's a FALSE positive due to backports") == "false"
    assert _verdict_of("Weighing it... could be real but likely FALSE") == "false"
    # substring traps must not trigger
    assert _verdict_of("really unclear, hard to say") == "ambiguous"
    assert _verdict_of("") == "ambiguous"


def test_promotes_inferred_when_judge_says_real():
    f = _finding("inferred")
    n = adjudicate_inferred([f], target="http://t", judge=lambda p: "REAL — version is vulnerable")
    assert n == 1
    assert f.verification_level == JUDGE_CONFIRMED_LEVEL
    assert f.needs_verification is False
    assert f.confidence >= 0.75


def test_keeps_inferred_when_judge_says_false():
    f = _finding("inferred")
    n = adjudicate_inferred([f], judge=lambda p: "FALSE — backported patch likely")
    assert n == 0
    assert f.verification_level == "inferred"
    assert f.needs_verification is True
    assert "FALSE POSITIVE" in f.evidence


def test_leaves_confirmed_and_heuristic_untouched():
    conf = _finding("confirmed")
    heur = _finding("heuristic")
    adjudicate_inferred([conf, heur], judge=lambda p: "REAL")  # judge would promote, but these aren't inferred
    assert conf.verification_level == "confirmed"
    assert heur.verification_level == "heuristic"


def test_ambiguous_leaves_untouched():
    f = _finding("inferred")
    n = adjudicate_inferred([f], judge=lambda p: "not sure, maybe")
    assert n == 0
    assert f.verification_level == "inferred"


def test_no_judge_is_noop(monkeypatch):
    # build_judge returns None in banca-safe → adjudicate is a no-op
    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    f = _finding("inferred")
    n = adjudicate_inferred([f], judge=None)  # banca-safe → build_judge None
    assert n == 0
    assert f.verification_level == "inferred"


def test_empty_judge_reply_leaves_untouched():
    f = _finding("inferred")
    n = adjudicate_inferred([f], judge=lambda p: "")  # judge unavailable for this one
    assert n == 0
    assert f.verification_level == "inferred"
