"""Tests for report generator."""

import pytest

from kryon.intelligence.models import (
    CVEDetail,
    Finding,
    MITREMapping,
    Severity,
)
from kryon.reporting.generator import ReportGenerator
from kryon.reporting.models import ReportConfig, ReportType


def _make_findings() -> list[Finding]:
    return [
        Finding(
            title="SQL Injection in Login",
            description="SQL injection vulnerability in /login endpoint",
            severity=Severity.CRITICAL,
            affected_asset="app.example.com",
            cvss_score=9.8,
            tool_source="sqlmap",
            remediation="Use parameterized queries",
            cve=CVEDetail(cve_id="CVE-2024-12345", cvss_score=9.8),
        ),
        Finding(
            title="Open SSH Port",
            description="Port 22 open with password auth",
            severity=Severity.MEDIUM,
            affected_asset="192.168.1.1",
            tool_source="nmap",
            remediation="Disable password auth, use key-based",
        ),
        Finding(
            title="Weak TLS Configuration",
            description="TLS 1.0 still enabled on web server",
            severity=Severity.HIGH,
            affected_asset="app.example.com",
            tool_source="testssl",
            remediation="Disable TLS 1.0 and 1.1",
        ),
        Finding(
            title="Directory Listing Enabled",
            description="Directory listing enabled on /uploads/",
            severity=Severity.LOW,
            affected_asset="app.example.com",
            tool_source="nikto",
        ),
        Finding(
            title="Server Version Disclosure",
            description="Apache/2.4.41 version disclosed in headers",
            severity=Severity.INFO,
            affected_asset="app.example.com",
            tool_source="whatweb",
        ),
    ]


@pytest.mark.asyncio
async def test_generate_technical_report():
    gen = ReportGenerator()
    config = ReportConfig(
        report_type=ReportType.TECHNICAL,
        client_name="Test Corp",
        target_scope="192.168.1.0/24",
    )
    html = await gen.generate(_make_findings(), config)
    assert "Informe Técnico de Seguridad" in html
    assert "Test Corp" in html
    assert "SQL Injection" in html
    assert "CRÍTICO" in html
    assert "MITRE" in html


@pytest.mark.asyncio
async def test_generate_executive_report():
    gen = ReportGenerator()
    config = ReportConfig(report_type=ReportType.EXECUTIVE, client_name="Acme Inc")
    html = await gen.generate(_make_findings(), config)
    assert "Informe Ejecutivo" in html
    assert "Acme Inc" in html
    assert "Panorama de riesgo" in html


@pytest.mark.asyncio
async def test_generate_compliance_report():
    gen = ReportGenerator()
    config = ReportConfig(
        report_type=ReportType.COMPLIANCE,
        include_compliance=["pci_dss"],
    )
    html = await gen.generate(_make_findings(), config)
    assert "PCI-DSS" in html
    assert "Cumplimiento" in html


@pytest.mark.asyncio
async def test_generate_empty_findings():
    gen = ReportGenerator()
    config = ReportConfig()
    html = await gen.generate([], config)
    assert "0 findings" in html.lower() or "0</strong>" in html


@pytest.mark.asyncio
async def test_mitre_enrichment():
    gen = ReportGenerator()
    findings = _make_findings()
    config = ReportConfig(include_mitre=True)
    await gen.generate(findings, config)
    # Generator should have enriched findings with MITRE mappings
    assert any(f.mitre for f in findings)
