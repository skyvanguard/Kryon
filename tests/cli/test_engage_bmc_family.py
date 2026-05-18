"""F199.E — BMC device family detection (HP iLO / Dell iDRAC / Supermicro IPMI).

Regression test for the false-positive observed in the Britimp POC pilot
on 2026-05-18: HP iLO at 172.18.201.223 was mis-classified as Linux
because of open SSH (22), HTTP (80), HTTPS (443) ports — the CIS Linux
playbook then emitted 7 FAILs against a vendor firmware that doesn't
even have a real shell.

The fix: detect the BMC banner string in any service `product` field
(or the iLO Federation port 17988) and add 'bmc' to the family list.
'bmc' is in the appliance exclusion set so 'linux' is NOT auto-added
when SSH is open on the same host.
"""

from __future__ import annotations

import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _detect_device_families


def _svc(host: str, port: int, service: str, product: str = "", state: str = "open") -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state=state, service=service, product=product)


# ---------------------------------------------------------------------------
# HP iLO — the exact case that surfaced the bug
# ---------------------------------------------------------------------------


class TestHpIloDetection:
    def test_ilo_banner_on_ssh_promotes_bmc_and_suppresses_linux(self):
        """HP iLO at 172.18.201.223 — the regression case."""
        services = [
            _svc("h", 22, "ssh", "HP Integrated Lights-Out mpSSH 0.2.1 (protocol 2.0)"),
            _svc("h", 80, "http", "HP Integrated Lights-Out web interface"),
            _svc("h", 443, "https", "HP Integrated Lights-Out web interface"),
        ]
        families = _detect_device_families(services)
        assert "bmc" in families
        # The whole point: linux must NOT be added.
        assert "linux" not in families

    def test_ilo_short_form_marker_detects(self):
        services = [_svc("h", 22, "ssh", "ilo mpssh 0.2.1")]
        families = _detect_device_families(services)
        assert "bmc" in families
        assert "linux" not in families

    def test_ilo_via_federation_port_17988(self):
        """Some iLO deployments don't expose 22/80/443 to the data plane
        but iLO Federation always uses 17988/tcp."""
        services = [_svc("h", 17988, "iLO-Federation", "")]
        families = _detect_device_families(services)
        assert "bmc" in families


# ---------------------------------------------------------------------------
# Dell iDRAC
# ---------------------------------------------------------------------------


class TestIdracDetection:
    def test_idrac_banner_promotes_bmc(self):
        services = [
            _svc("h", 22, "ssh", "iDRAC Remote Access Controller"),
            _svc("h", 443, "https", "iDRAC web interface"),
        ]
        families = _detect_device_families(services)
        assert "bmc" in families
        assert "linux" not in families

    def test_dell_remote_access_banner(self):
        services = [_svc("h", 22, "ssh", "Dell Remote Access Controller v7")]
        families = _detect_device_families(services)
        assert "bmc" in families


# ---------------------------------------------------------------------------
# Supermicro / ATEN IPMI
# ---------------------------------------------------------------------------


class TestSupermicroDetection:
    def test_supermicro_banner_promotes_bmc(self):
        services = [
            _svc("h", 22, "ssh", "Supermicro IPMI SSH server"),
            _svc("h", 443, "https", "Supermicro IPMI"),
        ]
        families = _detect_device_families(services)
        assert "bmc" in families
        assert "linux" not in families

    def test_aten_ipmi_banner(self):
        services = [_svc("h", 22, "ssh", "ATEN IPMI 1.0")]
        families = _detect_device_families(services)
        assert "bmc" in families


# ---------------------------------------------------------------------------
# Other BMCs
# ---------------------------------------------------------------------------


class TestOtherBmcDetection:
    def test_ami_megarac(self):
        services = [_svc("h", 443, "https", "AMI MegaRAC SP-X")]
        families = _detect_device_families(services)
        assert "bmc" in families

    def test_lenovo_xclarity(self):
        services = [_svc("h", 22, "ssh", "Lenovo XClarity Controller")]
        families = _detect_device_families(services)
        assert "bmc" in families

    def test_ipmi_udp_port_623(self):
        # nmap reports UDP 623 as open|filtered for IPMI hosts.
        services = [_svc("h", 623, "asf-rmcp", "")]
        families = _detect_device_families(services)
        assert "bmc" in families


# ---------------------------------------------------------------------------
# Negative cases — generic Linux must STILL be detected
# ---------------------------------------------------------------------------


class TestLinuxStillDetected:
    """The fix must NOT regress generic Linux detection. Hosts whose SSH
    banner is OpenSSH (no BMC marker) keep their `linux` family."""

    def test_ubuntu_openssh_remains_linux(self):
        services = [_svc("h", 22, "ssh", "OpenSSH 8.9p1 Ubuntu 3ubuntu0.15")]
        families = _detect_device_families(services)
        assert "linux" in families
        assert "bmc" not in families

    def test_debian_openssh_remains_linux(self):
        services = [_svc("h", 22, "ssh", "OpenSSH 9.2p1 Debian 2+deb12u7")]
        families = _detect_device_families(services)
        assert "linux" in families
        assert "bmc" not in families

    def test_proxmox_keeps_both_pve_and_linux(self):
        """Proxmox is a Linux distro — it's intentionally NOT in the
        appliance exclusion set."""
        services = [
            _svc("h", 22, "ssh", "OpenSSH for_Debian"),
            _svc("h", 8006, "https", "Proxmox Virtual Environment"),
        ]
        families = _detect_device_families(services)
        assert "proxmox" in families
        assert "linux" in families  # both, not either-or


# ---------------------------------------------------------------------------
# F199.I — Windows hosts with OpenSSH-for-Windows must NOT trigger linux
# ---------------------------------------------------------------------------


class TestWindowsSshDoesNotTriggerLinux:
    """The case from .13 in the Britimp POC: Windows host running
    OpenSSH for Windows 9.5 (sshd.exe, native Windows feature since
    Server 2019). Without the F199.I fix, has_ssh=True forces 'linux'
    on top of windows_ad → 7 Linux CIS FPs against a host that does
    not even have /etc/audit/."""

    def test_windows_ad_with_ssh_for_windows_no_linux(self):
        services = [
            _svc("h", 22, "ssh", "OpenSSH for_Windows_9.5"),
            _svc("h", 80, "http", "Microsoft IIS httpd 10.0"),
            _svc("h", 135, "msrpc", "Microsoft Windows RPC"),
            _svc("h", 139, "netbios-ssn", "Microsoft Windows netbios-ssn"),
            _svc("h", 389, "ldap", "Microsoft AD LDAP"),
            _svc("h", 445, "microsoft-ds", ""),
            _svc("h", 3389, "ms-wbt-server", ""),
        ]
        families = _detect_device_families(services)
        assert "windows_ad" in families
        assert "linux" not in families, f"Windows host should not get linux family; got {families}"

    def test_windows_member_with_ssh_no_linux(self):
        """Win Server 2019+ member server with native sshd enabled."""
        services = [
            _svc("h", 22, "ssh", "OpenSSH for_Windows_9.0"),
            _svc("h", 445, "microsoft-ds", ""),
            _svc("h", 5985, "wsman", ""),
        ]
        families = _detect_device_families(services)
        assert "windows" in families
        assert "linux" not in families


# ---------------------------------------------------------------------------
# Mixed scenarios
# ---------------------------------------------------------------------------


class TestMixedScenarios:
    def test_ilo_with_no_ssh_still_bmc(self):
        """Some iLO instances disable SSH entirely. We should still tag bmc."""
        services = [_svc("h", 443, "https", "HP Integrated Lights-Out web interface")]
        families = _detect_device_families(services)
        assert "bmc" in families
        assert "linux" not in families
