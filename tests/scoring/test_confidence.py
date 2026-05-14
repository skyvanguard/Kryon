"""F134 — Confidence scoring + cross-tool validation tests."""

from __future__ import annotations

from dataclasses import dataclass

from kryon.scoring.confidence import (
    annotate_confidence,
    compute_confidence,
)


@dataclass
class _F:
    rule_id: str = ""
    host: str = ""
    message: str = ""
    evidence: str = ""
    severity: str = "MEDIUM"
    confidence: float | None = None
    needs_verification: bool | None = None


# ---------------------------------------------------------------------------
# Deterministic findings → confidence 1.0
# ---------------------------------------------------------------------------


def test_phase2_http_finding_is_deterministic():
    annotations = compute_confidence([_F(rule_id="http-plaintext", host="x", message="m")])
    assert annotations[0].confidence == 1.0
    assert annotations[0].needs_verification is False
    assert annotations[0].source == "deterministic"


def test_compliance_pci_finding_is_deterministic():
    annotations = compute_confidence([_F(rule_id="PCI-DSS-2.2.7", host="x", message="m")])
    assert annotations[0].confidence == 1.0


def test_fortigate_finding_is_deterministic():
    annotations = compute_confidence([_F(rule_id="FGT-1.1", host="x", message="m")])
    assert annotations[0].confidence == 1.0


def test_info_disclosure_static_analyzer_is_deterministic():
    annotations = compute_confidence([_F(rule_id="INFO-009", host="x", message="m")])
    assert annotations[0].confidence == 1.0


# ---------------------------------------------------------------------------
# LLM-only findings → base 0.5 + needs_verification
# ---------------------------------------------------------------------------


def test_llm_finding_without_corroboration_has_base_confidence():
    annotations = compute_confidence([_F(rule_id="agent-finding", host="x", message="LLM said something")])
    assert annotations[0].confidence == 0.5
    assert annotations[0].needs_verification is True
    assert annotations[0].source == "llm"


def test_llm_finding_unknown_rule_id_not_treated_as_deterministic():
    annotations = compute_confidence([_F(rule_id="agent-WEB-001", host="x", message="m")])
    assert annotations[0].confidence < 1.0


# ---------------------------------------------------------------------------
# Corroboration boosts
# ---------------------------------------------------------------------------


def test_llm_finding_with_prefix_match_to_deterministic_gets_boost():
    findings = [
        _F(rule_id="PCI-DSS-2.2.7", host="x", message="weak SSH config"),
        # LLM emits with the "PCI-DSS-" prefix (same host) — corroborated.
        _F(rule_id="PCI-DSS-llm-CVE", host="x", message="related CVE"),
    ]
    annotations = compute_confidence(findings)
    # Both look deterministic by prefix — but that's OK: PCI-DSS-* is
    # always treated as deterministic regardless of who emitted it,
    # because that prefix is reserved to the compliance runner.
    assert annotations[1].confidence == 1.0
    assert annotations[1].source == "deterministic"


def test_llm_finding_with_different_host_no_boost():
    # An LLM finding with a non-reserved rule_id on a different host
    # gets no corroboration boost.
    findings = [
        _F(rule_id="http-plaintext", host="hostA", message="det http finding"),
        _F(rule_id="suspicious-something", host="hostB", message="LLM unrelated"),
    ]
    annotations = compute_confidence(findings)
    assert annotations[1].confidence == 0.5
    assert annotations[1].needs_verification is True


def test_llm_finding_with_text_overlap_gets_partial_boost():
    findings = [
        _F(rule_id="ssh-weak-kex", host="x", message="OpenSSH 8.9p1 weak kex algorithms"),
        _F(
            rule_id="cve-finding",
            host="x",
            message="OpenSSH 8.9p1 vulnerable to algorithms downgrade",
        ),
    ]
    annotations = compute_confidence(findings)
    # Text overlap ("openssh", "weak"/"algorithms") → at least 0.7.
    assert annotations[1].confidence >= 0.7


# ---------------------------------------------------------------------------
# annotate_confidence (in-place mutation)
# ---------------------------------------------------------------------------


def test_annotate_confidence_mutates_in_place():
    findings = [
        _F(rule_id="http-plaintext", host="x"),
        _F(rule_id="agent-finding", host="x"),
    ]
    annotate_confidence(findings)
    assert findings[0].confidence == 1.0
    assert findings[0].needs_verification is False
    assert findings[1].confidence == 0.5
    assert findings[1].needs_verification is True


def test_annotate_confidence_handles_empty_list():
    annotate_confidence([])  # must not raise


def test_annotate_confidence_skips_unmutable_objects():
    # Frozen objects: annotate_confidence must not raise.
    @dataclass(frozen=True)
    class _Frozen:
        rule_id: str
        host: str = "x"
        message: str = ""

    findings = [_Frozen(rule_id="http-plaintext")]
    annotate_confidence(findings)  # silently skips


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_finding_list_returns_empty():
    assert compute_confidence([]) == []


def test_missing_rule_id_handled_gracefully():
    findings = [_F(rule_id="", host="x", message="m")]
    annotations = compute_confidence(findings)
    # No rule_id → treated as LLM (low confidence).
    assert annotations[0].confidence == 0.5
    assert annotations[0].needs_verification is True


def test_severity_independent_of_confidence():
    # A LOW severity deterministic finding still gets confidence 1.0.
    findings = [_F(rule_id="http-plaintext", host="x", severity="LOW")]
    annotations = compute_confidence(findings)
    assert annotations[0].confidence == 1.0
