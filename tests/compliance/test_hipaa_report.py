"""HIPAA Security Rule mapping tests — technical safeguards auto-mapped,
process/physical safeguards stay manual (never auto-scored)."""

from __future__ import annotations

from kryon.compliance import map_findings_to_framework
from kryon.compliance.hipaa import HIPAA_CONTROLS, map_finding_to_hipaa_controls
from kryon.intelligence.models import Finding, Severity


def _f(title: str, description: str = "", severity: str = "high") -> Finding:
    return Finding(title=title, description=description, severity=Severity(severity), affected_asset="test-target")


# --- mapper: technical findings → technical safeguards ---


def test_weak_tls_maps_to_transmission_security():
    assert "164.312(e)(1)" in map_finding_to_hipaa_controls(_f("Weak TLS configuration"))


def test_access_control_maps_to_312a():
    assert "164.312(a)(1)" in map_finding_to_hipaa_controls(_f("Broken access control", "IDOR vulnerability"))


def test_vulnerability_maps_to_risk_management():
    assert "164.308(a)(1)(ii)(B)" in map_finding_to_hipaa_controls(_f("Outdated Apache with CVE-2024-5678"))


def test_default_creds_map_to_authentication():
    assert "164.312(d)" in map_finding_to_hipaa_controls(_f("Default credential found"))


def test_no_match_returns_empty():
    assert map_finding_to_hipaa_controls(_f("Custom issue", "something unrelated")) == []


# --- honest scope: process/physical controls are manual, never keyword-mapped ---


def test_process_controls_are_manual():
    manual = [c for c in HIPAA_CONTROLS if c.verdict_mode == "manual"]
    assert any(c.id == "164.308(b)(1)" for c in manual)  # BAAs
    assert any(c.id == "164.310(a)(1)" for c in manual)  # physical facility access


def test_no_finding_ever_maps_to_a_manual_control():
    manual_ids = {c.id for c in HIPAA_CONTROLS if c.verdict_mode == "manual"}
    # A broad technical finding must not touch any process/physical control.
    mapped = set(map_finding_to_hipaa_controls(_f("SQL injection + weak TLS + default creds + CVE-2024-1")))
    assert mapped.isdisjoint(manual_ids)


# --- report via the registry ---


def test_report_with_findings():
    findings = [_f("SQL Injection", "injection", "critical"), _f("Weak TLS", "outdated cipher")]
    report = map_findings_to_framework(findings, "hipaa")
    assert report.framework == "HIPAA Security Rule"
    assert report.controls_assessed == len(HIPAA_CONTROLS)
    assert report.controls_failed > 0


def test_report_no_findings_is_100pct():
    report = map_findings_to_framework([], "hipaa")
    assert report.controls_failed == 0
    assert report.compliance_percentage == 100.0
