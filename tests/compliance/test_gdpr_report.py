"""GDPR mapping tests — technical security measures (Art. 32 etc.) auto-mapped,
process/legal articles stay manual (never auto-scored)."""

from __future__ import annotations

from kryon.compliance import map_findings_to_framework
from kryon.compliance.gdpr import GDPR_CONTROLS, map_finding_to_gdpr_controls
from kryon.intelligence.models import Finding, Severity


def _f(title: str, description: str = "", severity: str = "high") -> Finding:
    return Finding(title=title, description=description, severity=Severity(severity), affected_asset="test-target")


# --- mapper: technical findings → Art. 32 / 25 / 33 / 5(1)(f) ---


def test_weak_tls_maps_to_encryption():
    assert "Art.32(1)(a)" in map_finding_to_gdpr_controls(_f("Weak TLS / unencrypted transport"))


def test_vulnerability_maps_to_testing():
    assert "Art.32(1)(d)" in map_finding_to_gdpr_controls(_f("Outdated nginx CVE-2024-9999"))


def test_data_exposure_maps_to_integrity_confidentiality():
    assert "Art.5(1)(f)" in map_finding_to_gdpr_controls(_f("Sensitive data exposure of PII"))


def test_incident_maps_to_breach_notification():
    assert "Art.33" in map_finding_to_gdpr_controls(_f("Active intrusion / breach detected"))


def test_no_match_returns_empty():
    assert map_finding_to_gdpr_controls(_f("Custom issue", "unrelated")) == []


# --- honest scope: legal/process articles are manual, never keyword-mapped ---


def test_process_articles_are_manual():
    manual_ids = {c.id for c in GDPR_CONTROLS if c.verdict_mode == "manual"}
    assert {"Art.6", "Art.7", "Art.15-22", "Art.30", "Art.37"} <= manual_ids


def test_no_finding_ever_maps_to_a_manual_article():
    manual_ids = {c.id for c in GDPR_CONTROLS if c.verdict_mode == "manual"}
    mapped = set(map_finding_to_gdpr_controls(_f("SQLi + weak TLS + data leak + CVE + breach")))
    assert mapped.isdisjoint(manual_ids)


# --- report via the registry ---


def test_report_with_findings():
    findings = [_f("Weak TLS", "cleartext"), _f("Sensitive data exposure", "PII leak", "critical")]
    report = map_findings_to_framework(findings, "gdpr")
    assert report.framework == "GDPR"
    assert report.controls_assessed == len(GDPR_CONTROLS)
    assert report.controls_failed > 0


def test_report_no_findings_is_100pct():
    report = map_findings_to_framework([], "gdpr")
    assert report.controls_failed == 0
    assert report.compliance_percentage == 100.0
