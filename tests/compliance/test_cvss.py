"""Tests for severity → CVSS v3.1 baseline mapping (F2.2)."""

from __future__ import annotations

from types import SimpleNamespace

from kryon.compliance.cvss import cvss_for_severity, cvss_score_for_severity
from kryon.reporting.findings_export import from_check_result, from_intel_finding


def test_known_severities_map_to_expected_scores():
    assert cvss_score_for_severity("CRITICAL") == 9.8
    assert cvss_score_for_severity("high") == 7.5  # case-insensitive
    assert cvss_score_for_severity("MEDIUM") == 5.3
    assert cvss_score_for_severity("LOW") == 3.1
    assert cvss_score_for_severity("INFO") == 0.0


def test_vector_is_v31():
    _, vector = cvss_for_severity("CRITICAL")
    assert vector.startswith("CVSS:3.1/")


def test_unknown_severity_falls_back_to_medium():
    assert cvss_score_for_severity("bogus") == 5.3


def test_check_result_row_has_cvss_from_severity():
    cr = SimpleNamespace(
        control_id="X",
        control_title="t",
        severity="high",
        verdict="fail",
        evidence_stdout="e",
        evidence_command="",
        remediation_static="r",
        host="h",
    )
    row = from_check_result(cr)
    assert row.cvss == "7.5"


def test_intel_finding_respects_measured_cvss():
    f = SimpleNamespace(
        id="F",
        title="t",
        severity="low",
        cvss_score=9.1,
        tool_source="",
        cve="",
        mitre="",
        affected_asset="",
        validation_status="",
        remediation="",
        evidence="",
    )
    row = from_intel_finding(f)
    assert row.cvss == "9.1"  # measured wins over severity-derived (3.1)


def test_info_severity_has_blank_cvss():
    cr = SimpleNamespace(
        control_id="X",
        control_title="t",
        severity="info",
        verdict="pass",
        evidence_stdout="",
        evidence_command="",
        remediation_static="",
        host="h",
    )
    assert from_check_result(cr).cvss == ""
