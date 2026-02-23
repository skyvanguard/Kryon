"""Tests for risk scorer."""

from kryon.evaluation.risk_scorer import RiskScorer
from kryon.intelligence.models import CVEDetail, Finding, MITREMapping, Severity


def _make_findings():
    return [
        Finding(title="SQLi", description="SQL injection", severity=Severity.CRITICAL, affected_asset="a"),
        Finding(title="XSS", description="Cross-site scripting", severity=Severity.HIGH, affected_asset="a"),
        Finding(title="Open Port", description="Port 80 open", severity=Severity.MEDIUM, affected_asset="b"),
        Finding(title="Info Disclosure", description="Version header", severity=Severity.INFO, affected_asset="b"),
    ]


def test_score_empty():
    scorer = RiskScorer()
    result = scorer.score_findings([])
    assert result.total_score == 0.0


def test_score_basic():
    scorer = RiskScorer()
    result = scorer.score_findings(_make_findings())
    assert result.total_score > 0
    assert result.severity_distribution["critical"] == 1
    assert result.severity_distribution["high"] == 1
    assert "SQLi" in result.top_risks


def test_score_all_critical():
    scorer = RiskScorer()
    findings = [
        Finding(title=f"Critical {i}", description="crit", severity=Severity.CRITICAL, affected_asset="x")
        for i in range(10)
    ]
    result = scorer.score_findings(findings)
    assert result.total_score == 100.0


def test_score_boost_epss():
    scorer = RiskScorer()
    findings = [
        Finding(
            title="Vuln",
            description="test",
            severity=Severity.HIGH,
            affected_asset="x",
            cve=CVEDetail(cve_id="CVE-2024-1", epss_score=0.9, cisa_kev=True, exploit_available=True),
        )
    ]
    result = scorer.score_findings(findings)
    # Should be boosted above base score
    base_findings = [Finding(title="Vuln", description="test", severity=Severity.HIGH, affected_asset="x")]
    base_result = scorer.score_findings(base_findings)
    assert result.total_score > base_result.total_score


def test_top_risks_limit():
    scorer = RiskScorer()
    findings = [
        Finding(title=f"Crit {i}", description="", severity=Severity.CRITICAL, affected_asset="x") for i in range(10)
    ]
    result = scorer.score_findings(findings)
    assert len(result.top_risks) <= 5
