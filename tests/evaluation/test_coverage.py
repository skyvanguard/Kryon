"""Tests for coverage analyzer."""

from kryon.evaluation.coverage import CoverageAnalyzer
from kryon.intelligence.models import Finding, MITREMapping, Severity


def test_coverage_basic():
    analyzer = CoverageAnalyzer()
    findings = [
        Finding(
            title="A",
            description="x",
            severity=Severity.HIGH,
            affected_asset="192.168.1.1",
            tool_source="nmap",
            mitre=[
                MITREMapping(
                    tactic="Discovery", tactic_id="TA0007", technique="T1046", technique_id="T1046", confidence=0.9
                )
            ],
        ),
        Finding(
            title="B",
            description="y",
            severity=Severity.MEDIUM,
            affected_asset="192.168.1.2",
            tool_source="nuclei",
            mitre=[
                MITREMapping(
                    tactic="Initial Access",
                    tactic_id="TA0001",
                    technique="T1190",
                    technique_id="T1190",
                    confidence=0.85,
                )
            ],
        ),
    ]
    metrics = analyzer.analyze(findings)
    assert metrics.assets_scanned == 2
    assert metrics.mitre_tactics_covered == 2
    assert metrics.mitre_techniques_tested == 2
    assert metrics.coverage_percent == 100.0


def test_coverage_with_total_assets():
    analyzer = CoverageAnalyzer()
    findings = [
        Finding(title="A", description="x", severity=Severity.LOW, affected_asset="1"),
    ]
    metrics = analyzer.analyze(findings, total_assets=10)
    assert metrics.total_assets == 10
    assert metrics.assets_scanned == 1
    assert metrics.coverage_percent == 10.0


def test_coverage_empty():
    analyzer = CoverageAnalyzer()
    metrics = analyzer.analyze([])
    assert metrics.assets_scanned == 0
    assert metrics.coverage_percent == 0.0
