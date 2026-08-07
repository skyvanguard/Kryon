"""F148 — Adversarial robustness filter tests."""

from __future__ import annotations

from dataclasses import dataclass

from kryon.scoring.adversarial import filter_unverified_llm_findings


@dataclass
class _F:
    rule_id: str = "x"
    host: str = "h"
    message: str = ""
    evidence: str = ""
    severity: str = "MEDIUM"
    confidence: float = 1.0
    needs_verification: bool = False


# ---------------------------------------------------------------------------
# Keep deterministic findings
# ---------------------------------------------------------------------------


def test_keeps_high_confidence_findings():
    findings = [_F(rule_id="http-plaintext", confidence=1.0, needs_verification=False)]
    result = filter_unverified_llm_findings(findings)
    assert result.kept_count == 1
    assert result.dropped_count == 0


def test_keeps_corroborated_llm_findings():
    findings = [_F(rule_id="cve-1", confidence=0.85, needs_verification=False)]
    result = filter_unverified_llm_findings(findings)
    assert result.kept_count == 1


# ---------------------------------------------------------------------------
# Drop unverified low-confidence findings without evidence
# ---------------------------------------------------------------------------


def test_drops_low_confidence_no_evidence():
    findings = [_F(rule_id="bogus", confidence=0.5, needs_verification=True, evidence="", message="")]
    result = filter_unverified_llm_findings(findings)
    assert result.kept_count == 0
    assert result.dropped_count == 1
    assert "no meaningful evidence" in result.reasons["bogus|h"]


def test_keeps_low_confidence_with_meaningful_evidence():
    findings = [
        _F(
            rule_id="bogus",
            confidence=0.5,
            needs_verification=True,
            evidence="response body returned 500 with stack trace including database error",
        )
    ]
    result = filter_unverified_llm_findings(findings)
    assert result.kept_count == 1


def test_drops_below_threshold_with_short_evidence():
    findings = [_F(rule_id="bogus", confidence=0.4, needs_verification=True, evidence="x")]
    result = filter_unverified_llm_findings(findings)
    assert result.dropped_count == 1


# ---------------------------------------------------------------------------
# Strict mode
# ---------------------------------------------------------------------------


def test_strict_mode_drops_all_needs_verification():
    findings = [
        _F(rule_id="A", confidence=0.5, needs_verification=True, evidence="long enough evidence text here"),
        _F(rule_id="B", confidence=1.0, needs_verification=False),
    ]
    result = filter_unverified_llm_findings(findings, strict=True)
    assert result.kept_count == 1
    assert result.kept[0].rule_id == "B"


def test_strict_mode_via_env(monkeypatch):
    monkeypatch.setenv("KRYON_ADVERSARIAL_STRICT", "true")
    findings = [_F(rule_id="A", confidence=0.5, needs_verification=True, evidence="long enough evidence text here")]
    result = filter_unverified_llm_findings(findings)
    assert result.kept_count == 0


def test_non_strict_mode_default(monkeypatch):
    monkeypatch.delenv("KRYON_ADVERSARIAL_STRICT", raising=False)
    findings = [_F(rule_id="A", confidence=0.5, needs_verification=True, evidence="long enough evidence text here")]
    result = filter_unverified_llm_findings(findings)
    assert result.kept_count == 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_findings_returns_empty_result():
    result = filter_unverified_llm_findings([])
    assert result.kept_count == 0
    assert result.dropped_count == 0


def test_finding_without_confidence_field_treated_as_high():
    @dataclass
    class _Minimal:
        rule_id: str = "X"
        host: str = "h"
        message: str = "m"

    result = filter_unverified_llm_findings([_Minimal()])
    assert result.kept_count == 1


def test_threshold_override_works():
    findings = [_F(rule_id="A", confidence=0.6, needs_verification=True, evidence="")]
    # Default threshold 0.7 → drop. Override to 0.5 → keep.
    drop_result = filter_unverified_llm_findings(findings, drop_threshold=0.7)
    assert drop_result.dropped_count == 1
    keep_result = filter_unverified_llm_findings(findings, drop_threshold=0.5)
    assert keep_result.kept_count == 1


def test_reasons_keyed_by_rule_and_host():
    findings = [
        _F(rule_id="A", host="h1", confidence=0.3, needs_verification=True, evidence=""),
        _F(rule_id="A", host="h2", confidence=0.3, needs_verification=True, evidence=""),
    ]
    result = filter_unverified_llm_findings(findings)
    assert "A|h1" in result.reasons
    assert "A|h2" in result.reasons
