"""Tests for scan comparator."""

from kryon.intelligence.models import Finding, Severity
from kryon.evaluation.comparator import ScanComparator


def test_compare_no_changes():
    comp = ScanComparator()
    findings = [Finding(title="A", description="x", severity=Severity.HIGH, affected_asset="1")]
    result = comp.compare(findings, findings)
    assert len(result.new_findings) == 0
    assert len(result.remediated_findings) == 0
    assert len(result.persistent_findings) == 1
    assert result.risk_delta == 0.0


def test_compare_new_findings():
    comp = ScanComparator()
    before = [Finding(title="A", description="x", severity=Severity.HIGH, affected_asset="1")]
    after = [
        Finding(title="A", description="x", severity=Severity.HIGH, affected_asset="1"),
        Finding(title="B", description="y", severity=Severity.CRITICAL, affected_asset="2"),
    ]
    result = comp.compare(before, after)
    assert len(result.new_findings) == 1
    assert result.new_findings[0].title == "B"
    assert result.risk_delta > 0  # worsening


def test_compare_remediated():
    comp = ScanComparator()
    before = [
        Finding(title="A", description="x", severity=Severity.CRITICAL, affected_asset="1"),
        Finding(title="B", description="y", severity=Severity.HIGH, affected_asset="2"),
    ]
    after = [Finding(title="A", description="x", severity=Severity.CRITICAL, affected_asset="1")]
    result = comp.compare(before, after)
    assert len(result.remediated_findings) == 1
    assert result.remediated_findings[0].title == "B"
    assert result.risk_delta < 0  # improving


def test_compare_empty():
    comp = ScanComparator()
    result = comp.compare([], [])
    assert result.risk_delta == 0.0
    assert "0 persistent" not in result.summary or result.summary == ""


def test_compare_summary():
    comp = ScanComparator()
    before = [Finding(title="A", description="x", severity=Severity.HIGH, affected_asset="1")]
    after = [Finding(title="B", description="y", severity=Severity.MEDIUM, affected_asset="2")]
    result = comp.compare(before, after, before_id="s1", after_id="s2")
    assert "1 new" in result.summary
    assert "1 remediated" in result.summary
    assert result.scan_before_id == "s1"
