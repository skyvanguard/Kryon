"""F202.N — BGP exposure detector.

Surfaced POC Example BASE .203.1: router edge con TCP/179 abierto al
data plane. Read-only TCP connect probe (banca-safe); no BGP OPEN
message enviado.

Severidad MEDIUM (banner grab no confirma auth status — siempre
recomienda TCP-AO + MD5 + ACL + prefix-list).
"""

from __future__ import annotations

import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _check_bgp_exposure


def _svc(port: int, service: str = "", product: str = "", state: str = "open") -> DiscoveredService:
    return DiscoveredService(host="10.0.0.1", port=port, state=state, service=service, product=product)


# ---------------------------------------------------------------------------
# Positive — BGP detected
# ---------------------------------------------------------------------------


class TestBgpDetection:
    def test_port_179_open_flags_medium(self):
        finding = _check_bgp_exposure(_svc(179, "bgp"))
        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert finding.cwe == "CWE-200"
        assert finding.rule_id == "bgp-exposed-data-plane"

    def test_port_179_with_tcpwrapped_still_flags(self):
        """Example .203.1 case: nmap reported tcpwrapped, no banner."""
        finding = _check_bgp_exposure(_svc(179, "bgp", product=""))
        assert finding is not None
        assert "TCP/179" in finding.message
        assert "tcpwrapped" in finding.evidence.lower() or "(suprimido" in finding.evidence

    def test_port_179_with_cisco_banner(self):
        finding = _check_bgp_exposure(_svc(179, "bgp", product="Cisco IOS 17.x"))
        assert finding is not None
        assert "Cisco" in finding.evidence

    def test_remediation_mentions_tcp_ao(self):
        finding = _check_bgp_exposure(_svc(179))
        assert finding is not None
        # Banking-mandatory hardening must mention canonical practices
        assert "TCP-AO" in finding.remediation
        assert "MD5" in finding.remediation
        assert "prefix-list" in finding.remediation
        assert "ACL" in finding.remediation

    def test_remediation_mentions_rpki(self):
        finding = _check_bgp_exposure(_svc(179))
        assert finding is not None
        assert "RPKI" in finding.remediation

    def test_remediation_mentions_multiple_vendors(self):
        """Cisco / Juniper / FortiGate / MikroTik — Example tiene FortiGate
        + posible MikroTik en el edge."""
        finding = _check_bgp_exposure(_svc(179))
        assert finding is not None
        rem = finding.remediation
        assert "Cisco" in rem
        assert "Juniper" in rem
        assert "FortiGate" in rem
        assert "MikroTik" in rem


# ---------------------------------------------------------------------------
# Negative — wrong port / closed
# ---------------------------------------------------------------------------


class TestNegative:
    def test_non_179_port_no_flag(self):
        assert _check_bgp_exposure(_svc(22, "ssh")) is None
        assert _check_bgp_exposure(_svc(80, "http")) is None
        assert _check_bgp_exposure(_svc(53, "domain")) is None

    def test_closed_179_no_flag(self):
        assert _check_bgp_exposure(_svc(179, "bgp", state="closed")) is None

    def test_filtered_179_no_flag(self):
        assert _check_bgp_exposure(_svc(179, "bgp", state="filtered")) is None
