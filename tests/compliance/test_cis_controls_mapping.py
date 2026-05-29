"""Tests for finding→CIS Controls v8.1 safeguard mapping + report builder."""

from __future__ import annotations

from kryon.compliance import map_findings_to_framework
from kryon.compliance.cis_controls import (
    CIS_CONTROLS,
    map_finding_to_cis_controls,
)
from kryon.intelligence.models import Finding, Severity

_VALID_IDS = {c.id for c in CIS_CONTROLS}


def _finding(title: str, description: str = "", severity: str = "high") -> Finding:
    return Finding(title=title, description=description, severity=Severity(severity), affected_asset="test-target")


class TestFindingMapping:
    def test_default_credential_maps_to_4_7(self):
        ids = map_finding_to_cis_controls(_finding("Default credential admin/admin"))
        assert "CIS-4.7" in ids

    def test_mfa_maps_to_access_control(self):
        ids = map_finding_to_cis_controls(_finding("Missing MFA on admin panel", "no two-factor"))
        assert "CIS-6.5" in ids

    def test_patch_maps_to_vuln_mgmt(self):
        ids = map_finding_to_cis_controls(_finding("Outdated nginx", "unpatched CVE-2024-1234"))
        assert "CIS-7.4" in ids

    def test_pentest_maps_to_control_18(self):
        ids = map_finding_to_cis_controls(_finding("Penetration test finding", "red team exploit"))
        assert any(i.startswith("CIS-18.") for i in ids)

    def test_no_match_returns_empty(self):
        ids = map_finding_to_cis_controls(_finding("Totally unrelated cosmetic note"))
        assert ids == []

    def test_all_mapped_ids_exist_in_catalog(self):
        # Stress every keyword group: nothing maps to a non-existent safeguard.
        probe = _finding(
            "SQL injection XSS encryption tls backup malware ransomware firewall "
            "siem phishing service provider incident response penetration test "
            "default credential mfa patch logging asset inventory data classification",
            "comprehensive keyword probe",
        )
        ids = map_finding_to_cis_controls(probe)
        assert ids
        assert all(i in _VALID_IDS for i in ids)


class TestReportBuilder:
    def test_framework_name(self):
        report = map_findings_to_framework([], "cis_controls")
        assert report.framework == "CIS Controls v8.1"

    def test_assesses_153_safeguards(self):
        report = map_findings_to_framework([], "cis_controls")
        assert report.controls_assessed == 153
        assert report.compliance_percentage == 100.0

    def test_finding_fails_relevant_safeguards(self):
        report = map_findings_to_framework(
            [_finding("Default credential + weak MFA on admin", "admin/admin, no 2fa")],
            "cis_controls",
        )
        failed = {e.control_id for e in report.evidence if e.status == "fail"}
        assert "CIS-4.7" in failed
        assert report.controls_failed > 0
        assert report.controls_passed == 153 - report.controls_failed
