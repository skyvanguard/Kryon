"""Tests for SOC 2 Type II compliance mapping and reporting."""

from __future__ import annotations

import pytest

from kryon.compliance import map_findings_to_framework
from kryon.compliance.soc2 import SOC2_TSC_CONTROLS, map_finding_to_soc2_controls
from kryon.intelligence.models import Finding, Severity
from kryon.reporting.sections.soc2_report import render_soc2_report


def _make_finding(title: str, description: str = "", severity: str = "high") -> Finding:
    return Finding(title=title, description=description, severity=Severity(severity), affected_asset="test-target")


class TestSOC2Mapping:
    def test_access_control_maps_to_cc6(self):
        finding = _make_finding("Broken access control", "IDOR vulnerability found")
        controls = map_finding_to_soc2_controls(finding)
        assert any(c.startswith("CC6") for c in controls)

    def test_weak_ssl_maps_to_cc6_7(self):
        finding = _make_finding("Weak TLS configuration")
        controls = map_finding_to_soc2_controls(finding)
        assert "CC6.7" in controls

    def test_vulnerability_maps_to_cc7_3(self):
        finding = _make_finding("Outdated Apache with CVE-2024-5678")
        controls = map_finding_to_soc2_controls(finding)
        assert "CC7.3" in controls

    def test_no_match_returns_empty(self):
        finding = _make_finding("Custom issue", "Something unrelated")
        controls = map_finding_to_soc2_controls(finding)
        assert controls == []

    def test_data_exposure_maps_to_c1(self):
        finding = _make_finding("Sensitive data exposure in API response")
        controls = map_finding_to_soc2_controls(finding)
        assert "C1.1" in controls


class TestSOC2Report:
    def test_report_with_findings(self):
        findings = [
            _make_finding("SQL Injection", "injection flaw", "critical"),
            _make_finding("Weak TLS", "outdated cipher", "high"),
        ]
        report = map_findings_to_framework(findings, "soc2")
        assert report.controls_assessed == len(SOC2_TSC_CONTROLS)
        assert report.controls_failed > 0

    def test_report_no_findings(self):
        report = map_findings_to_framework([], "soc2")
        assert report.controls_failed == 0
        assert report.compliance_percentage == 100.0

    def test_html_generation(self):
        findings = [_make_finding("Privilege escalation", severity="high")]
        html = render_soc2_report(findings)
        assert "SOC 2 Type II" in html
        assert "Controls Assessed" in html

    def test_all_tsc_categories(self):
        categories = {c.category for c in SOC2_TSC_CONTROLS}
        assert "Security" in categories
        assert "Availability" in categories
        assert "Privacy" in categories

    def test_report_framework_name(self):
        report = map_findings_to_framework([], "soc2")
        assert report.framework == "SOC 2 Type II"

    def test_compliance_percentage_calculation(self):
        findings = [
            _make_finding("Broken access control", severity="critical"),
            _make_finding("Data exposure", "sensitive data leak", severity="high"),
        ]
        report = map_findings_to_framework(findings, "soc2")
        assert 0 < report.compliance_percentage < 100
