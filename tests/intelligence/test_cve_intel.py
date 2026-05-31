"""F2 — tests for cve_intel offensive triage (pure logic, no network)."""

from __future__ import annotations

from kryon.intelligence.models import CVEDetail
from kryon.tools.knowledge.cve_intel import _CVE_RE, _verdict


def test_cve_regex_detects_id():
    assert _CVE_RE.search("look at CVE-2024-3094 now").group(0) == "CVE-2024-3094"
    assert _CVE_RE.search("CVE-2021-44228").group(0) == "CVE-2021-44228"


def test_cve_regex_ignores_non_cve():
    assert _CVE_RE.search("apache struts rce") is None
    assert _CVE_RE.search("") is None


def test_verdict_kev_is_pursue():
    """CISA KEV alone (actively exploited) → PURSUE."""
    v = _verdict(CVEDetail(cve_id="CVE-2024-3094", cisa_kev=True))
    assert v["priority"] == "PURSUE"
    assert v["pursue_score"] >= 50
    assert any("KEV" in r for r in v["reasons"])


def test_verdict_critical_cvss_alone_is_low():
    """A critical CVSS with no exploit/KEV/EPSS is NOT actionable → LOW."""
    v = _verdict(CVEDetail(cve_id="CVE-2024-0001", cvss_score=9.8))
    assert v["priority"] == "LOW"


def test_verdict_exploit_plus_epss_is_consider():
    """Public exploit (25) + high EPSS (15) = 40 → CONSIDER."""
    d = CVEDetail(
        cve_id="CVE-2024-0002",
        exploit_available=True,
        exploit_refs=["https://exploit-db.com/x"],
        epss_score=0.72,
    )
    v = _verdict(d)
    assert v["priority"] == "CONSIDER"
    assert 20 <= v["pursue_score"] < 50


def test_verdict_kev_plus_exploit_tops_out():
    """KEV (50) + exploit (25) → well into PURSUE with multiple reasons."""
    d = CVEDetail(
        cve_id="CVE-2021-44228",
        cisa_kev=True,
        exploit_available=True,
        exploit_refs=["a", "b"],
        cvss_score=10.0,
    )
    v = _verdict(d)
    assert v["priority"] == "PURSUE"
    assert len(v["reasons"]) >= 3
