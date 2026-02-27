"""Tests for PCI-DSS v4.0 compliance mapping and reporting."""

from __future__ import annotations

import pytest

from kryon.compliance import map_findings_to_framework
from kryon.compliance.pci_dss import PCI_DSS_V4_CONTROLS, map_finding_to_pci_controls
from kryon.intelligence.models import Finding, Severity
from kryon.reporting.sections.pci_dss_report import render_pci_dss_report


def _make_finding(title: str, description: str = "", severity: str = "high") -> Finding:
    return Finding(title=title, description=description, severity=Severity(severity), affected_asset="test-target")


class TestPCIDSSMapping:
    def test_sql_injection_maps_to_6_2_4(self):
        finding = _make_finding("SQL Injection in login form")
        controls = map_finding_to_pci_controls(finding)
        assert "6.2.4" in controls

    def test_weak_ssl_maps_to_4_2_1(self):
        finding = _make_finding("Weak TLS configuration", "Server supports weak cipher suites")
        controls = map_finding_to_pci_controls(finding)
        assert "4.2.1" in controls

    def test_default_password_maps_to_2_2_2(self):
        finding = _make_finding("Default credential detected", "admin/admin login works")
        controls = map_finding_to_pci_controls(finding)
        assert "2.2.2" in controls

    def test_no_match_returns_empty(self):
        finding = _make_finding("Custom issue", "Something unrelated to PCI")
        controls = map_finding_to_pci_controls(finding)
        assert controls == []

    def test_multiple_controls_matched(self):
        finding = _make_finding("Outdated software with CVE-2024-1234", "Unpatched Apache server")
        controls = map_finding_to_pci_controls(finding)
        assert "6.3.1" in controls
        assert "6.3.3" in controls


class TestPCIDSSReport:
    def test_report_with_findings(self):
        findings = [
            _make_finding("SQL Injection", "Found SQLi in login", "critical"),
            _make_finding("Weak TLS", "TLS 1.0 enabled", "high"),
        ]
        report = map_findings_to_framework(findings, "pci_dss")
        assert report.controls_assessed == len(PCI_DSS_V4_CONTROLS)
        assert report.controls_failed > 0
        assert report.controls_passed > 0

    def test_report_no_findings_all_pass(self):
        report = map_findings_to_framework([], "pci_dss")
        assert report.controls_failed == 0
        assert report.compliance_percentage == 100.0

    def test_html_generation(self):
        findings = [_make_finding("XSS vulnerability", "Reflected XSS", "medium")]
        html = render_pci_dss_report(findings)
        assert "PCI-DSS v4.0" in html
        assert "Controls Assessed" in html
        assert "<table" in html

    def test_compliance_percentage(self):
        findings = [
            _make_finding("SQL Injection", severity="critical"),
            _make_finding("Default credential on router", severity="high"),
            _make_finding("Weak password policy", severity="medium"),
        ]
        report = map_findings_to_framework(findings, "pci_dss")
        assert 0 < report.compliance_percentage < 100

    def test_all_controls_covered(self):
        assert len(PCI_DSS_V4_CONTROLS) >= 20

    def test_report_framework_name(self):
        report = map_findings_to_framework([], "pci_dss")
        assert report.framework == "PCI-DSS v4.0"
