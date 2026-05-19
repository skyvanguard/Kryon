"""F202.H — Cross-DC config drift detection.

Toma findings indexados por host y emite findings de drift cuando los
DCs (Windows AD) de un mismo dominio tienen postura DNS o de
servicios ASIMETRICA. Surface ground truth: Britimp POC pilot
2026-05-18, .205 vs .5 — mismo dominio britimp.com.py pero distinto
DNSSEC validation status + distintos puertos abiertos.

CWE-1188 (Insecure Default Initialization of Resource).
"""

from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    Finding,
    _DC_DRIFT_DNS_RULES,
    _is_domain_controller_host,
    _rule_ids_present,
    diff_dc_dns_posture,
)


def _f(rule_id: str, host: str = "h", sev: str = "MEDIUM", cwe: str = "CWE-0") -> Finding:
    """Minimal Finding helper for test fixtures."""
    return Finding(cwe=cwe, severity=sev, host=host, rule_id=rule_id, message="")


# ---------------------------------------------------------------------------
# DC detection heuristic
# ---------------------------------------------------------------------------


class TestIsDomainController:
    def test_host_with_ad_rule_is_dc(self):
        findings = [_f("AD-1.1"), _f("WIN-1.1")]
        assert _is_domain_controller_host(findings) is True

    def test_host_with_only_windows_rules_is_not_dc(self):
        """Member server has WIN-* but no AD-* -> not a DC."""
        findings = [_f("WIN-1.1"), _f("WIN-2.3")]
        assert _is_domain_controller_host(findings) is False

    def test_host_with_no_rules_is_not_dc(self):
        assert _is_domain_controller_host([]) is False

    def test_host_with_only_dns_rules_is_not_dc(self):
        """A bare DNS server (not AD) shouldn't be classified as DC."""
        findings = [_f("dns-open-resolver"), _f("dnssec-validation-disabled")]
        assert _is_domain_controller_host(findings) is False


# ---------------------------------------------------------------------------
# Below-threshold (single DC, no peers)
# ---------------------------------------------------------------------------


class TestBelowThreshold:
    def test_single_dc_no_drift(self):
        host_findings = {
            "172.18.201.205": [_f("AD-1.1"), _f("dns-open-resolver")],
        }
        assert diff_dc_dns_posture(host_findings) == []

    def test_no_dcs_no_drift(self):
        host_findings = {
            "10.0.0.5": [_f("WIN-1.1")],
            "10.0.0.6": [_f("dns-open-resolver")],
        }
        assert diff_dc_dns_posture(host_findings) == []


# ---------------------------------------------------------------------------
# DNS rule drift — the Britimp .205 vs .5 case
# ---------------------------------------------------------------------------


class TestDnsRuleDrift:
    def test_britimp_dnssec_drift_scenario(self):
        """Reproduces the .205 vs .5 case exactly:
          - both DCs have dns-open-resolver (consistent)
          - only .205 has dnssec-validation-disabled (drift)
        Expected: 1 finding for the DNSSEC drift, NONE for the
        consistent dns-open-resolver.
        """
        host_findings = {
            "172.18.201.205": [_f("AD-1.1"), _f("dns-open-resolver"), _f("dnssec-validation-disabled")],
            "172.18.201.5": [_f("AD-1.1"), _f("dns-open-resolver")],
        }
        drift = diff_dc_dns_posture(host_findings)
        # Exactly one drift finding for the DNSSEC asymmetry
        drift_rules = [f.rule_id for f in drift]
        assert "dc-drift-dnssec-validation-disabled" in drift_rules
        assert "dc-drift-dns-open-resolver" not in drift_rules  # consistent -> no drift

    def test_drift_severity_for_dnssec_is_high(self):
        host_findings = {
            "10.0.0.1": [_f("AD-1.1"), _f("dnssec-validation-disabled")],
            "10.0.0.2": [_f("AD-1.1")],
        }
        drift = diff_dc_dns_posture(host_findings)
        dnssec_drift = [f for f in drift if f.rule_id == "dc-drift-dnssec-validation-disabled"]
        assert len(dnssec_drift) == 1
        assert dnssec_drift[0].severity == "HIGH"
        assert dnssec_drift[0].cwe == "CWE-1188"

    def test_drift_severity_for_chaos_leak_is_medium(self):
        host_findings = {
            "10.0.0.1": [_f("AD-1.1"), _f("dns-chaos-leak")],
            "10.0.0.2": [_f("AD-1.1")],
        }
        drift = diff_dc_dns_posture(host_findings)
        chaos_drift = [f for f in drift if f.rule_id == "dc-drift-dns-chaos-leak"]
        assert len(chaos_drift) == 1
        assert chaos_drift[0].severity == "MEDIUM"

    def test_all_drift_rules_in_table_can_be_detected(self):
        """Smoke test: for each rule in _DC_DRIFT_DNS_RULES, build
        a 2-DC fixture where the rule is asymmetric and verify drift
        is emitted."""
        for rule_id, expected_sev, _label in _DC_DRIFT_DNS_RULES:
            host_findings = {
                "10.0.0.1": [_f("AD-1.1"), _f(rule_id)],
                "10.0.0.2": [_f("AD-1.1")],
            }
            drift = diff_dc_dns_posture(host_findings)
            drift_for_this = [f for f in drift if f.rule_id == f"dc-drift-{rule_id}"]
            assert len(drift_for_this) == 1, (
                f"No drift detected for asymmetric rule {rule_id!r}"
            )
            assert drift_for_this[0].severity == expected_sev


# ---------------------------------------------------------------------------
# Service-presence drift (HTTP / SSH on one DC only)
# ---------------------------------------------------------------------------


class TestServiceDrift:
    def test_iis_plaintext_drift(self):
        """The .5 case: HTTP plaintext on .5 but not on .205."""
        host_findings = {
            "172.18.201.205": [_f("AD-1.1")],
            "172.18.201.5": [_f("AD-1.1"), _f("http-plaintext", host="172.18.201.5:80", sev="HIGH")],
        }
        drift = diff_dc_dns_posture(host_findings)
        iis_drift = [f for f in drift if f.rule_id == "dc-drift-service-http-plaintext"]
        assert len(iis_drift) == 1
        assert iis_drift[0].severity == "MEDIUM"
        assert "172.18.201.5" in iis_drift[0].message
        assert "172.18.201.205" in iis_drift[0].message

    def test_ssh_drift(self):
        """The .5 case: SSH-for-Windows on .5 but not on .205."""
        host_findings = {
            "172.18.201.205": [_f("AD-1.1")],
            "172.18.201.5": [_f("AD-1.1"), _f("ssh-banner-visible", host="172.18.201.5:22")],
        }
        drift = diff_dc_dns_posture(host_findings)
        ssh_drift = [f for f in drift if f.rule_id == "dc-drift-service-ssh-banner-visible"]
        assert len(ssh_drift) == 1


# ---------------------------------------------------------------------------
# Symmetric posture — no drift
# ---------------------------------------------------------------------------


class TestSymmetricPosture:
    def test_identical_dns_findings_no_drift(self):
        """Both DCs have the same vulns -> consistent bug (still
        bad) but NOT drift."""
        host_findings = {
            "10.0.0.1": [_f("AD-1.1"), _f("dns-open-resolver"), _f("dnssec-validation-disabled")],
            "10.0.0.2": [_f("AD-1.1"), _f("dns-open-resolver"), _f("dnssec-validation-disabled")],
        }
        drift = diff_dc_dns_posture(host_findings)
        # No drift findings at all — perfectly symmetric (even if both bad)
        assert drift == []

    def test_both_dcs_clean_no_drift(self):
        host_findings = {
            "10.0.0.1": [_f("AD-1.1")],
            "10.0.0.2": [_f("AD-1.1")],
        }
        assert diff_dc_dns_posture(host_findings) == []


# ---------------------------------------------------------------------------
# Multiple DCs (>2) — should still detect drift correctly
# ---------------------------------------------------------------------------


class TestThreeDcs:
    def test_three_dcs_two_with_dnssec_drift(self):
        """3 DCs total, 2 of them have dnssec-validation-disabled,
        one does not -> drift detected."""
        host_findings = {
            "10.0.0.1": [_f("AD-1.1"), _f("dnssec-validation-disabled")],
            "10.0.0.2": [_f("AD-1.1"), _f("dnssec-validation-disabled")],
            "10.0.0.3": [_f("AD-1.1")],
        }
        drift = diff_dc_dns_posture(host_findings)
        dnssec_drift = [f for f in drift if f.rule_id == "dc-drift-dnssec-validation-disabled"]
        assert len(dnssec_drift) == 1
        # All three DCs should be referenced in the host field
        assert "10.0.0.1" in dnssec_drift[0].host
        assert "10.0.0.2" in dnssec_drift[0].host
        assert "10.0.0.3" in dnssec_drift[0].host


# ---------------------------------------------------------------------------
# Helper — _rule_ids_present
# ---------------------------------------------------------------------------


class TestRuleIdsPresent:
    def test_deduplicates(self):
        findings = [_f("AD-1.1"), _f("AD-1.1"), _f("WIN-2.3")]
        ids = _rule_ids_present(findings)
        assert ids == {"AD-1.1", "WIN-2.3"}

    def test_empty(self):
        assert _rule_ids_present([]) == set()


# ---------------------------------------------------------------------------
# Drift table sanity
# ---------------------------------------------------------------------------


class TestDriftTableSanity:
    def test_all_dns_rule_ids_unique(self):
        rule_ids = [r[0] for r in _DC_DRIFT_DNS_RULES]
        assert len(rule_ids) == len(set(rule_ids))

    def test_severity_values_valid(self):
        for _rule_id, sev, _label in _DC_DRIFT_DNS_RULES:
            assert sev in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
