"""F202.R — SIEM agent activity check.

Surfaced POC Britimp 2026-05-19: Wazuh VM-Ubuntu-Wazuh STOPPED en el
cluster Proxmox. SIEM apagado = blind spot total de eventos seguridad.

Severities:
  - CRITICAL: Wazuh installed pero agent inactive (peor caso — falsa
    sensacion de monitoring)
  - HIGH: No SIEM agent corriendo (sin monitoring infrastructure)
  - MEDIUM: SIEM heterogeneo (filebeat sin wazuh, etc.)
  - No finding: Wazuh active OR (auditd + rsyslog)
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    _check_siem_activity,
    _SIEM_PACKAGES_TO_CHECK,
)


def _fake_ssh(output: str):
    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=output, stderr="")

    return _run


# Realistic outputs
_OUT_WAZUH_INACTIVE = """\
wazuh-agent=inactive
filebeat=missing
auditd=inactive
osquery=missing
rsyslog=active
syslog-ng=missing
ossec_dir=yes
wazuh_dir=yes"""

_OUT_NO_SIEM = """\
wazuh-agent=missing
filebeat=missing
auditd=missing
osquery=missing
rsyslog=missing
syslog-ng=missing
ossec_dir=no
wazuh_dir=no"""

_OUT_WAZUH_ACTIVE = """\
wazuh-agent=active
filebeat=missing
auditd=active
osquery=missing
rsyslog=active
syslog-ng=missing
ossec_dir=yes
wazuh_dir=yes"""

_OUT_AUDITD_RSYSLOG_ONLY = """\
wazuh-agent=missing
filebeat=missing
auditd=active
osquery=missing
rsyslog=active
syslog-ng=missing
ossec_dir=no
wazuh_dir=no"""

_OUT_HETEROGENEOUS = """\
wazuh-agent=missing
filebeat=active
auditd=missing
osquery=missing
rsyslog=missing
syslog-ng=missing
ossec_dir=no
wazuh_dir=no"""


# ---------------------------------------------------------------------------
# CRITICAL — Wazuh installed pero apagado (POC Britimp case)
# ---------------------------------------------------------------------------


class TestWazuhInstalledButInactive:
    def test_britimp_wazuh_apagado_es_critical(self):
        """The exact POC Britimp case: VM-Wazuh STOPPED -> agents en
        hosts del cluster quedan inactive con /var/ossec installed."""
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_ssh(_OUT_WAZUH_INACTIVE)):
            finding = _check_siem_activity(
                host="172.18.201.115",
                ssh_target="root@172.18.201.115",
                ssh_key="/tmp/id_ed25519",
                ssh_password=None,
            )
        assert finding is not None
        assert finding.severity == "CRITICAL"
        assert finding.cwe == "CWE-778"
        assert finding.rule_id == "siem-wazuh-installed-inactive"
        assert "blind spot" in finding.message.lower()
        assert "PCI-DSS Req 10" in finding.remediation


# ---------------------------------------------------------------------------
# HIGH — sin ningun SIEM
# ---------------------------------------------------------------------------


class TestNoSiemAtAll:
    def test_no_siem_is_high(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_ssh(_OUT_NO_SIEM)):
            finding = _check_siem_activity(
                host="10.0.0.5",
                ssh_target="ubuntu@10.0.0.5",
                ssh_key="/tmp/id_ed25519",
                ssh_password=None,
            )
        assert finding is not None
        assert finding.severity == "HIGH"
        assert finding.rule_id == "siem-no-agent"

    def test_no_siem_remediation_mentions_wazuh_install(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_ssh(_OUT_NO_SIEM)):
            finding = _check_siem_activity(
                host="10.0.0.5",
                ssh_target="ubuntu@10.0.0.5",
                ssh_key="/tmp/id_ed25519",
                ssh_password=None,
            )
        assert finding is not None
        assert "Wazuh" in finding.remediation
        assert "auditd" in finding.remediation


# ---------------------------------------------------------------------------
# OK — no finding (Wazuh active OR auditd+rsyslog)
# ---------------------------------------------------------------------------


class TestOkScenarios:
    def test_wazuh_active_no_finding(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_ssh(_OUT_WAZUH_ACTIVE)):
            assert _check_siem_activity(
                host="10.0.0.5",
                ssh_target="root@10.0.0.5",
                ssh_key="/tmp/key",
                ssh_password=None,
            ) is None

    def test_auditd_plus_rsyslog_no_finding(self):
        """Minimum viable SIEM baseline: auditd + remote rsyslog OK."""
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_ssh(_OUT_AUDITD_RSYSLOG_ONLY)):
            assert _check_siem_activity(
                host="10.0.0.5",
                ssh_target="ubuntu@10.0.0.5",
                ssh_key="/tmp/key",
                ssh_password=None,
            ) is None


# ---------------------------------------------------------------------------
# MEDIUM — heterogeneous SIEM
# ---------------------------------------------------------------------------


class TestHeterogeneousSiem:
    def test_filebeat_alone_is_medium(self):
        """filebeat sin wazuh y sin auditd+rsyslog -> heterogeneo."""
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_ssh(_OUT_HETEROGENEOUS)):
            finding = _check_siem_activity(
                host="10.0.0.5",
                ssh_target="ubuntu@10.0.0.5",
                ssh_key="/tmp/key",
                ssh_password=None,
            )
        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert finding.rule_id == "siem-heterogeneous"


# ---------------------------------------------------------------------------
# Gate — graceful degradation
# ---------------------------------------------------------------------------


class TestGracefulDegradation:
    def test_no_ssh_target_no_call(self):
        """Sin ssh_target, check no se ejecuta."""
        # No need to patch — should never reach subprocess.run
        assert _check_siem_activity(
            host="10.0.0.5",
            ssh_target=None,
            ssh_key=None,
            ssh_password=None,
        ) is None

    def test_ssh_empty_output_no_finding(self):
        """SSH connect falla (sin output) -> graceful skip, no finding."""
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_ssh("")):
            assert _check_siem_activity(
                host="10.0.0.5",
                ssh_target="root@10.0.0.5",
                ssh_key="/tmp/key",
                ssh_password=None,
            ) is None


# ---------------------------------------------------------------------------
# Configuration table sanity
# ---------------------------------------------------------------------------


class TestConfigSanity:
    def test_wazuh_in_packages(self):
        assert "wazuh-agent" in _SIEM_PACKAGES_TO_CHECK

    def test_filebeat_in_packages(self):
        assert "filebeat" in _SIEM_PACKAGES_TO_CHECK

    def test_auditd_in_packages(self):
        assert "auditd" in _SIEM_PACKAGES_TO_CHECK
