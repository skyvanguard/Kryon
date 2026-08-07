"""F152 — Tool-output grounding tests."""

from __future__ import annotations

from dataclasses import dataclass

from kryon.validation.grounding import (
    apply_grounding,
    check_grounding,
    extract_citations,
)


@dataclass
class _F:
    rule_id: str = "x"
    severity: str = "HIGH"
    host: str = "h"
    message: str = ""
    evidence: str = ""
    remediation: str = ""
    confidence: float = 1.0
    needs_verification: bool = False


# ---------------------------------------------------------------------------
# extract_citations
# ---------------------------------------------------------------------------


def test_extract_call_id_citation():
    citations = extract_citations("Detected via call_id: abc123def456")
    assert len(citations) >= 1


def test_extract_step_citation():
    citations = extract_citations("Confirmed at step 5 of the scan")
    assert len(citations) >= 1


def test_extract_spanish_segun_output():
    citations = extract_citations("según output de nuclei_scan se encontró RCE")
    assert len(citations) >= 1


def test_extract_english_according_to():
    citations = extract_citations("According to nuclei_scan output, port 80 is open.")
    assert len(citations) >= 1


def test_extract_based_on_tool():
    citations = extract_citations("Based on nuclei_scan output the server is vulnerable.")
    assert len(citations) >= 1


def test_extract_from_tool_output():
    citations = extract_citations("from whatweb_scan output it's Apache.")
    assert len(citations) >= 1


def test_extract_no_citation_returns_empty():
    citations = extract_citations("The server has SQL injection vulnerabilities.")
    assert citations == ()


def test_extract_empty_input():
    assert extract_citations("") == ()


# ---------------------------------------------------------------------------
# check_grounding
# ---------------------------------------------------------------------------


def test_grounded_finding_with_citation():
    f = _F(message="step 3 confirmed RCE", evidence="curl returned 500")
    r = check_grounding(f)
    assert r.grounded is True
    assert len(r.citations) >= 1


def test_ungrounded_finding_without_citation():
    f = _F(message="The server is vulnerable to SQL injection")
    r = check_grounding(f)
    assert r.grounded is False
    assert "no citation" in r.reason


def test_dict_finding_supported():
    d = {"rule_id": "x", "evidence": "call_id: xyz123"}
    r = check_grounding(d)
    assert r.grounded is True


def test_empty_finding_ungrounded():
    f = _F()
    r = check_grounding(f)
    assert r.grounded is False


# ---------------------------------------------------------------------------
# apply_grounding penalty
# ---------------------------------------------------------------------------


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("KRYON_REQUIRE_GROUNDING", raising=False)
    findings = [_F(confidence=1.0, needs_verification=False, message="no citation here")]
    n = apply_grounding(findings)
    assert n == 0
    assert findings[0].confidence == 1.0
    assert findings[0].needs_verification is False


def test_explicit_enabled_caps_ungrounded(monkeypatch):
    monkeypatch.delenv("KRYON_REQUIRE_GROUNDING", raising=False)
    findings = [_F(confidence=0.85, needs_verification=False, message="no citation")]
    n = apply_grounding(findings, enabled=True, cap=0.3)
    assert n == 1
    assert findings[0].confidence == 0.3
    assert findings[0].needs_verification is True


def test_grounded_finding_not_capped():
    findings = [_F(confidence=0.85, message="call_id: xyz123 confirmed")]
    n = apply_grounding(findings, enabled=True, cap=0.3)
    assert n == 0
    assert findings[0].confidence == 0.85


def test_mixed_batch_only_ungrounded_capped():
    findings = [
        _F(confidence=1.0, message="grounded — step 5 fired"),
        _F(confidence=0.85, message="no cite"),
        _F(confidence=1.0, evidence="based on nuclei_scan output it's vulnerable"),
    ]
    n = apply_grounding(findings, enabled=True, cap=0.3)
    assert n == 1
    assert findings[0].confidence == 1.0  # cited
    assert findings[1].confidence == 0.3  # capped
    assert findings[2].confidence == 1.0  # cited


def test_env_enabled_picks_up_default_cap(monkeypatch):
    monkeypatch.setenv("KRYON_REQUIRE_GROUNDING", "true")
    monkeypatch.delenv("KRYON_GROUNDING_CONFIDENCE_CAP", raising=False)
    findings = [_F(message="no citation")]
    apply_grounding(findings)
    assert findings[0].confidence == 0.3


def test_env_cap_override(monkeypatch):
    monkeypatch.setenv("KRYON_REQUIRE_GROUNDING", "true")
    monkeypatch.setenv("KRYON_GROUNDING_CONFIDENCE_CAP", "0.5")
    findings = [_F(confidence=1.0, message="no citation")]
    apply_grounding(findings)
    assert findings[0].confidence == 0.5


def test_dict_findings_mutated_in_place():
    findings = [{"confidence": 1.0, "evidence": "no citation", "needs_verification": False}]
    apply_grounding(findings, enabled=True, cap=0.3)
    assert findings[0]["confidence"] == 0.3
    assert findings[0]["needs_verification"] is True


def test_empty_findings_no_op():
    assert apply_grounding([], enabled=True) == 0


def test_juice_shop_r1_invented_finding_capped():
    """The exact finding R1 produced against Juice Shop in F150.B —
    no citation to any tool output. Should be capped."""
    f = _F(
        rule_id="CVE-2020-10445",
        severity="CRITICAL",
        host="http://juice_shop:3000",
        message="Server improperly handles user inputs that can cause buffer overflow",
        evidence="The application allows untrusted serialized data to be deserialized",
        remediation="Implement strict input validation",
        confidence=1.0,
        needs_verification=False,
    )
    n = apply_grounding([f], enabled=True, cap=0.3)
    assert n == 1
    assert f.confidence == 0.3
    assert f.needs_verification is True
