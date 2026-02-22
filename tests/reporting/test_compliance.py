"""Tests for compliance mapping."""

from kryon.intelligence.models import Finding, Severity
from kryon.reporting.sections.compliance import (
    PCI_DSS_MAPPING,
    MITIC_MAPPING,
    ISO_27001_MAPPING,
    render_compliance_mapping,
)


def _make_findings() -> list[Finding]:
    return [
        Finding(title="SQL Injection", description="SQL injection found", severity=Severity.CRITICAL, affected_asset="x"),
        Finding(title="Weak SSL", description="TLS 1.0 enabled, weak cipher suites", severity=Severity.HIGH, affected_asset="x"),
        Finding(title="Default Credentials", description="admin/admin default password", severity=Severity.HIGH, affected_asset="x"),
        Finding(title="Open Port 3306", description="Port scan reveals open MySQL", severity=Severity.MEDIUM, affected_asset="x"),
    ]


def test_pci_dss_mapping_has_entries():
    assert len(PCI_DSS_MAPPING) >= 15


def test_mitic_mapping_has_entries():
    assert len(MITIC_MAPPING) >= 8


def test_iso_27001_mapping_has_entries():
    assert len(ISO_27001_MAPPING) >= 10


def test_render_pci_dss():
    html = render_compliance_mapping(_make_findings(), "pci_dss")
    assert "PCI-DSS" in html
    assert "6.2.4" in html  # SQL injection req


def test_render_mitic():
    html = render_compliance_mapping(_make_findings(), "mitic")
    assert "MITIC" in html


def test_render_iso_27001():
    html = render_compliance_mapping(_make_findings(), "iso_27001")
    assert "ISO 27001" in html


def test_render_unknown_framework():
    html = render_compliance_mapping(_make_findings(), "unknown_framework")
    assert "Unknown compliance framework" in html
