"""Contract for kryon.repl.findings_bridge — engine findings → intelligence.Finding."""

from __future__ import annotations

from types import SimpleNamespace

from kryon.intelligence.models import Severity, ValidationStatus
from kryon.repl.findings_bridge import (
    engine_finding_to_intelligence,
    engine_findings_to_intelligence,
)


def test_maps_engage_finding_shape() -> None:
    f = SimpleNamespace(
        cwe="CWE-79",
        rule_id="xss_reflected",
        severity="HIGH",
        host="www.example.com",
        message="XSS reflection on /#/search",
        evidence="<script>",
    )
    out = engine_finding_to_intelligence(f)
    assert out.severity is Severity.HIGH
    assert out.affected_asset == "www.example.com"
    assert out.tool_source == "xss_reflected"
    assert "CWE-79" in out.title and "XSS reflection" in out.title
    assert out.evidence == "<script>"
    # Deterministic findings are CONFIRMED, not UNVALIDATED.
    assert out.validation_status is ValidationStatus.CONFIRMED
    assert out.validation_method == "deterministic_engine"


def test_maps_banking_finding_shape() -> None:
    # BankingFinding uses cwe_id/probe_id/url/title.
    f = SimpleNamespace(cwe_id="CWE-89", probe_id="sqli", severity="critical", url="https://x/y", title="SQLi")
    out = engine_finding_to_intelligence(f)
    assert out.severity is Severity.CRITICAL
    assert out.affected_asset == "https://x/y"
    assert out.tool_source == "sqli"


def test_list_skips_bad_and_keeps_good() -> None:
    good = SimpleNamespace(cwe="CWE-1", rule_id="r", severity="low", host="h", message="m", evidence="")

    class _Boom:
        @property
        def severity(self):
            raise RuntimeError("boom")

    out = engine_findings_to_intelligence([good, _Boom(), good])
    assert len(out) == 2  # the boom one is skipped


def test_severity_defaults_to_info() -> None:
    f = SimpleNamespace(cwe="", rule_id="r", severity="weird", host="h", message="m", evidence="")
    assert engine_finding_to_intelligence(f).severity is Severity.INFO


def test_enrichment_cvss_and_remediation() -> None:
    # C1 — the deterministic finding gets a CVSS score + a remediation fallback
    # by CWE so the report never ships empty columns.
    f = SimpleNamespace(cwe="CWE-79", rule_id="xss", severity="HIGH", host="h", message="XSS", evidence="")
    out = engine_finding_to_intelligence(f)
    assert out.cvss_score is not None and out.cvss_score > 0
    assert "CSP" in out.remediation or "Escapar" in out.remediation


def test_numeric_cwe_is_normalized() -> None:
    # engage findings sometimes carry a bare "1390" — normalize to CWE-1390 so
    # the remediation lookup + report labelling work.
    f = SimpleNamespace(cwe_id="1390", probe_id="spf-missing", severity="MEDIUM", url="d", title="SPF missing")
    out = engine_finding_to_intelligence(f)
    assert "CWE-1390" in out.title
    assert "SPF" in out.remediation or "DMARC" in out.remediation


def test_source_remediation_is_preserved() -> None:
    f = SimpleNamespace(
        cwe="CWE-79", rule_id="x", severity="high", host="h", message="m", evidence="", remediation="custom fix"
    )
    assert engine_finding_to_intelligence(f).remediation == "custom fix"
