"""F202.O — Proxmox cluster drift detector.

Surfaced POC Britimp 2026-05-19: cluster `britimp-cluster` con 3
nodos PVE en versiones DIFERENTES:
  - .115 proxmox2: PVE 9.1.4
  - .200 pve-britimp: PVE 8.4.16 (aislado del cluster!)
  - .222 pve-torre-prod: PVE 9.1.8

Comparado a F202.H (DC drift), F202.O detecta drift cluster Proxmox.
Funcion pura, invocada por orchestration externa.
"""

from __future__ import annotations

import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    _PROXMOX_CLUSTER_DRIFT_RULES,
    Finding,
    _is_proxmox_host,
    diff_proxmox_cluster_posture,
)


def _f(rule_id: str, host: str = "h", sev: str = "MEDIUM", cwe: str = "CWE-0", evidence: str = "") -> Finding:
    return Finding(cwe=cwe, severity=sev, host=host, rule_id=rule_id, message="", evidence=evidence)


# ---------------------------------------------------------------------------
# Proxmox host detection
# ---------------------------------------------------------------------------


class TestIsProxmoxHost:
    def test_host_with_pve_rule_is_proxmox(self):
        assert _is_proxmox_host([_f("PVE-1.2")]) is True

    def test_host_with_only_cis_is_not_proxmox(self):
        assert _is_proxmox_host([_f("10.2.1"), _f("2.2.2")]) is False

    def test_empty_findings_not_proxmox(self):
        assert _is_proxmox_host([]) is False


# ---------------------------------------------------------------------------
# Below threshold
# ---------------------------------------------------------------------------


class TestBelowThreshold:
    def test_single_pve_no_drift(self):
        host_findings = {"10.0.0.1": [_f("PVE-1.2"), _f("PVE-2.1")]}
        assert diff_proxmox_cluster_posture(host_findings) == []

    def test_no_pve_no_drift(self):
        host_findings = {
            "10.0.0.1": [_f("WIN-1.1")],
            "10.0.0.2": [_f("10.2.1")],
        }
        assert diff_proxmox_cluster_posture(host_findings) == []


# ---------------------------------------------------------------------------
# Britimp POC scenario — 3 nodes with drift
# ---------------------------------------------------------------------------


class TestBritimpClusterDrift:
    def test_britimp_python_simplehttp_drift(self):
        """POC Britimp: python http.server CRITICAL solo en .200,
        no en .115 ni .222 -> drift CRITICAL."""
        host_findings = {
            "172.18.201.115": [_f("PVE-1.2"), _f("PVE-2.1"), _f("PVE-3.1"), _f("sshd-permit-root-login")],
            "172.18.201.200": [
                _f("PVE-1.2"),
                _f("PVE-2.1"),
                _f("PVE-3.1"),
                _f("sshd-permit-root-login"),
                _f("python-simplehttp-directory-listing", sev="CRITICAL"),
            ],
            "172.18.201.222": [_f("PVE-1.2"), _f("PVE-2.1"), _f("PVE-3.1"), _f("sshd-permit-root-login")],
        }
        drift = diff_proxmox_cluster_posture(host_findings)
        # python-simplehttp asymmetric -> drift CRITICAL
        python_drift = [f for f in drift if f.rule_id == "pve-cluster-drift-python-simplehttp-directory-listing"]
        assert len(python_drift) == 1
        assert python_drift[0].severity == "CRITICAL"
        # Consistent rules (PVE-1.2, sshd-permit-root) should NOT drift
        assert not any(f.rule_id == "pve-cluster-drift-PVE-1.2" for f in drift)
        assert not any(f.rule_id == "pve-cluster-drift-sshd-permit-root-login" for f in drift)


# ---------------------------------------------------------------------------
# PVE version drift (cross-cluster version diff)
# ---------------------------------------------------------------------------


class TestPveVersionDrift:
    def test_three_versions_in_cluster_flags_high(self):
        """Britimp .115 = 9.1.4, .200 = 8.4.16, .222 = 9.1.8."""
        host_findings = {
            "172.18.201.115": [_f("PVE-1.2", evidence="pveversion: pve-manager/9.1.4/...")],
            "172.18.201.200": [_f("PVE-1.2", evidence="pveversion: pve-manager/8.4.16/...")],
            "172.18.201.222": [_f("PVE-1.2", evidence="pveversion: pve-manager/9.1.8/...")],
        }
        drift = diff_proxmox_cluster_posture(host_findings)
        version_drift = [f for f in drift if f.rule_id == "pve-cluster-drift-version"]
        assert len(version_drift) == 1
        assert version_drift[0].severity == "HIGH"
        # All 3 versions mentioned
        assert "9.1.4" in version_drift[0].evidence
        assert "8.4.16" in version_drift[0].evidence
        assert "9.1.8" in version_drift[0].evidence

    def test_same_version_no_drift(self):
        host_findings = {
            "10.0.0.1": [_f("PVE-1.2", evidence="pveversion: pve-manager/9.1.4/...")],
            "10.0.0.2": [_f("PVE-1.2", evidence="pveversion: pve-manager/9.1.4/...")],
        }
        drift = diff_proxmox_cluster_posture(host_findings)
        version_drift = [f for f in drift if f.rule_id == "pve-cluster-drift-version"]
        assert len(version_drift) == 0


# ---------------------------------------------------------------------------
# Symmetric posture — no drift
# ---------------------------------------------------------------------------


class TestSymmetric:
    def test_identical_findings_no_drift(self):
        host_findings = {
            "10.0.0.1": [_f("PVE-1.2"), _f("PVE-2.1"), _f("sshd-permit-root-login")],
            "10.0.0.2": [_f("PVE-1.2"), _f("PVE-2.1"), _f("sshd-permit-root-login")],
        }
        drift = diff_proxmox_cluster_posture(host_findings)
        # Solo posibles drifts son rule-based; con findings identicos: no
        rule_drift = [f for f in drift if f.rule_id.startswith("pve-cluster-drift-PVE-")]
        assert rule_drift == []

    def test_both_clean_no_drift(self):
        host_findings = {
            "10.0.0.1": [_f("PVE-1.2")],  # marker pero sin failures realtivos
            "10.0.0.2": [_f("PVE-1.2")],
        }
        assert diff_proxmox_cluster_posture(host_findings) == []


# ---------------------------------------------------------------------------
# Drift severity por rule_id correctness
# ---------------------------------------------------------------------------


class TestDriftSeverityMapping:
    def test_sshd_drift_is_critical(self):
        """sshd-permit-root-login asymmetric debe ser CRITICAL."""
        host_findings = {
            "10.0.0.1": [_f("PVE-1.2"), _f("sshd-permit-root-login")],
            "10.0.0.2": [_f("PVE-1.2")],
        }
        drift = diff_proxmox_cluster_posture(host_findings)
        ssh_drift = [f for f in drift if f.rule_id == "pve-cluster-drift-sshd-permit-root-login"]
        assert len(ssh_drift) == 1
        assert ssh_drift[0].severity == "CRITICAL"

    def test_pve_1_2_drift_is_high(self):
        host_findings = {
            "10.0.0.1": [_f("PVE-2.1"), _f("PVE-1.2")],  # both — diferente from other
            "10.0.0.2": [_f("PVE-2.1")],
        }
        drift = diff_proxmox_cluster_posture(host_findings)
        pve12 = [f for f in drift if f.rule_id == "pve-cluster-drift-PVE-1.2"]
        assert len(pve12) == 1
        assert pve12[0].severity == "HIGH"

    def test_pve_6_1_drift_is_medium(self):
        host_findings = {
            "10.0.0.1": [_f("PVE-1.2"), _f("PVE-6.1")],
            "10.0.0.2": [_f("PVE-1.2")],
        }
        drift = diff_proxmox_cluster_posture(host_findings)
        pve61 = [f for f in drift if f.rule_id == "pve-cluster-drift-PVE-6.1"]
        assert len(pve61) == 1
        assert pve61[0].severity == "MEDIUM"


# ---------------------------------------------------------------------------
# Table sanity
# ---------------------------------------------------------------------------


class TestTableSanity:
    def test_pve_rules_in_table(self):
        rule_ids = [r[0] for r in _PROXMOX_CLUSTER_DRIFT_RULES]
        assert "PVE-1.2" in rule_ids
        assert "PVE-2.1" in rule_ids
        assert "sshd-permit-root-login" in rule_ids
        assert "python-simplehttp-directory-listing" in rule_ids

    def test_severities_valid(self):
        for _rule_id, sev, _label in _PROXMOX_CLUSTER_DRIFT_RULES:
            assert sev in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
