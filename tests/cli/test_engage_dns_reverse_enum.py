"""F202.F — DNS reverse zone enumeration detection.

Sexto check de la hexalogia DNS (F202.A/B/C/D/E/F). Walks a
deterministic 10-IP sample del /24 del target, captura PTR records
internos, y eleva a HIGH cuando detecta keywords sensibles (banking,
payment, swift, prod, db, vault).

Validacion contra .205: si el DC resuelve PTR de todo el /24 a
hostnames internos -> recon barato pre-targeting de servicios
criticos.
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    DiscoveredService,
    _check_reverse_dns_enum,
    _is_generic_ptr,
    _REVERSE_FAILURE_MARKERS,
    _REVERSE_HIT_THRESHOLD,
    _REVERSE_PROBE_OCTETS,
    _SENSITIVE_HOSTNAME_KEYWORDS,
    _try_ptr_query,
)


def _svc(host: str = "172.18.201.205", port: int = 53, state: str = "open") -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state=state, service="domain", product="")


def _ptr_response(hostname: str, ip: str) -> str:
    """Build a realistic Windows nslookup PTR response."""
    return (
        "Server:  UnKnown\n"
        "Address:  172.18.201.205\n"
        "\n"
        f"Name:    {hostname}\n"
        f"Address:  {ip}\n"
    )


_NXDOMAIN_OUT = (
    "Server:  UnKnown\n"
    "Address:  172.18.201.205\n"
    "\n"
    "*** UnKnown can't find 172.18.201.99: Non-existent domain\n"
)


# ---------------------------------------------------------------------------
# Positive — enum succeeds, MEDIUM
# ---------------------------------------------------------------------------


class TestEnumMedium:
    def test_three_generic_hostnames_flag_medium(self):
        """3 PTRs resolved with generic-but-internal names -> MEDIUM
        (no sensitive keywords)."""
        ptr_map = {
            "172.18.201.5": "host5.internal.example",
            "172.18.201.10": "host10.internal.example",
            "172.18.201.50": "bastion.internal.example",
        }

        def _multi(cmd, **_kw):
            # nslookup <ip> <dns>
            ip = cmd[1]
            if ip in ptr_map:
                return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_response(ptr_map[ip], ip), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_NXDOMAIN_OUT, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_reverse_dns_enum(_svc())

        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert finding.cwe == "CWE-200"
        assert finding.rule_id == "dns-reverse-enum"
        assert "host5" in finding.evidence or "bastion" in finding.evidence


# ---------------------------------------------------------------------------
# Positive — sensitive keywords elevate to HIGH
# ---------------------------------------------------------------------------


class TestEnumHigh:
    def test_banking_keyword_elevates_to_high(self):
        ptr_map = {
            "172.18.201.5": "dc02.britimp.com.py",
            "172.18.201.50": "bastion.britimp.com.py",
            "172.18.201.150": "core-banking-db.britimp.com.py",
            "172.18.201.200": "swift-gateway.britimp.com.py",
        }

        def _multi(cmd, **_kw):
            ip = cmd[1]
            if ip in ptr_map:
                return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_response(ptr_map[ip], ip), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_NXDOMAIN_OUT, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_reverse_dns_enum(_svc())

        assert finding is not None
        assert finding.severity == "HIGH"
        assert "swift-gateway" in finding.evidence or "core-banking" in finding.evidence
        # Message should hint at sensitive function
        assert "sensible" in finding.message.lower() or "alta prioridad" in finding.message.lower()

    def test_postgres_keyword_elevates(self):
        ptr_map = {
            "172.18.201.10": "vmhost.example.local",
            "172.18.201.100": "app01.example.local",
            "172.18.201.150": "postgres-prod.example.local",
        }

        def _multi(cmd, **_kw):
            ip = cmd[1]
            if ip in ptr_map:
                return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_response(ptr_map[ip], ip), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_NXDOMAIN_OUT, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_reverse_dns_enum(_svc())

        assert finding is not None
        assert finding.severity == "HIGH"

    def test_vault_keyword_elevates(self):
        ptr_map = {
            "172.18.201.1": "gateway.example.local",
            "172.18.201.10": "app01.example.local",
            "172.18.201.100": "vault-prod.example.local",
        }

        def _multi(cmd, **_kw):
            ip = cmd[1]
            if ip in ptr_map:
                return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_response(ptr_map[ip], ip), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_NXDOMAIN_OUT, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_reverse_dns_enum(_svc())

        assert finding is not None
        assert finding.severity == "HIGH"


# ---------------------------------------------------------------------------
# Negative — below threshold / generic / restricted
# ---------------------------------------------------------------------------


class TestNegative:
    def test_only_two_hits_below_threshold(self):
        ptr_map = {
            "172.18.201.5": "dc02.example.local",
            "172.18.201.50": "bastion.example.local",
        }

        def _multi(cmd, **_kw):
            ip = cmd[1]
            if ip in ptr_map:
                return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_response(ptr_map[ip], ip), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_NXDOMAIN_OUT, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            assert _check_reverse_dns_enum(_svc()) is None

    def test_all_nxdomain_no_flag(self):
        with patch(
            "kryon.cli.engage.subprocess.run",
            side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=_NXDOMAIN_OUT, stderr=""),
        ):
            assert _check_reverse_dns_enum(_svc()) is None

    def test_all_refused_no_flag(self):
        refused = "*** UnKnown can't find 172.18.201.10: Query refused\n"
        with patch(
            "kryon.cli.engage.subprocess.run",
            side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=refused, stderr=""),
        ):
            assert _check_reverse_dns_enum(_svc()) is None

    def test_all_generic_ip_derived_hostnames_no_flag(self):
        """Hostnames like `host-172-18-201-5.dyn.isp.net` are
        IP-derived auto-PTRs — no real internal info disclosed.
        Must NOT flag even with 10+ hits."""
        def _multi(cmd, **_kw):
            ip = cmd[1]
            octets = ip.split(".")
            generic = f"host-{'-'.join(octets)}.dyn.isp.net"
            return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_response(generic, ip), stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            assert _check_reverse_dns_enum(_svc()) is None

    def test_in_addr_arpa_hostnames_no_flag(self):
        def _multi(cmd, **_kw):
            ip = cmd[1]
            octets = ip.split(".")
            generic = ".".join(reversed(octets)) + ".in-addr.arpa"
            return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_response(generic, ip), stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            assert _check_reverse_dns_enum(_svc()) is None


# ---------------------------------------------------------------------------
# Gate — service / port / IPv4 validity
# ---------------------------------------------------------------------------


class TestGate:
    def test_non_dns_port_skipped(self):
        svc = DiscoveredService(host="h", port=80, state="open", service="http", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_reverse_dns_enum(svc) is None

    def test_closed_port_skipped(self):
        svc = DiscoveredService(host="172.18.201.205", port=53, state="closed", service="domain", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_reverse_dns_enum(svc) is None

    def test_non_ipv4_target_skipped(self):
        """Hostname target (not an IPv4) -> we can't derive a /24
        sweep. Skip silently."""
        svc = DiscoveredService(host="dns.example.com", port=53, state="open", service="domain", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_reverse_dns_enum(svc) is None


# ---------------------------------------------------------------------------
# Helpers — _try_ptr_query / _is_generic_ptr
# ---------------------------------------------------------------------------


class TestTryPtrQuery:
    def test_parses_name_line(self):
        out = _ptr_response("dc01.britimp.com.py", "172.18.201.205")
        with patch(
            "kryon.cli.engage.subprocess.run",
            side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=out, stderr=""),
        ):
            assert _try_ptr_query("172.18.201.205", "172.18.201.5") == "dc01.britimp.com.py"

    def test_refused_returns_none(self):
        out = "*** UnKnown can't find 172.18.201.5: Query refused\n"
        with patch(
            "kryon.cli.engage.subprocess.run",
            side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=out, stderr=""),
        ):
            assert _try_ptr_query("172.18.201.205", "172.18.201.5") is None

    def test_nxdomain_returns_none(self):
        with patch(
            "kryon.cli.engage.subprocess.run",
            side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=_NXDOMAIN_OUT, stderr=""),
        ):
            assert _try_ptr_query("172.18.201.205", "172.18.201.5") is None


class TestIsGenericPtr:
    def test_in_addr_arpa_is_generic(self):
        assert _is_generic_ptr("5.201.18.172.in-addr.arpa", "172.18.201.5") is True

    def test_ip_derived_hostname_is_generic(self):
        assert _is_generic_ptr("host-172-18-201-5.dyn.isp.net", "172.18.201.5") is True

    def test_named_hostname_is_not_generic(self):
        assert _is_generic_ptr("dc01.britimp.com.py", "172.18.201.5") is False
        assert _is_generic_ptr("bastion-prod.example.local", "172.18.201.50") is False


# ---------------------------------------------------------------------------
# Probe set + sensitive keyword sanity
# ---------------------------------------------------------------------------


class TestConstants:
    def test_probe_octets_count(self):
        assert len(_REVERSE_PROBE_OCTETS) == 10

    def test_probe_octets_unique(self):
        assert len(_REVERSE_PROBE_OCTETS) == len(set(_REVERSE_PROBE_OCTETS))

    def test_threshold_at_least_three(self):
        assert _REVERSE_HIT_THRESHOLD >= 3

    def test_sensitive_keywords_include_banking(self):
        assert any("bank" in kw or "swift" in kw for kw in _SENSITIVE_HOSTNAME_KEYWORDS)

    def test_sensitive_keywords_lowercase(self):
        for kw in _SENSITIVE_HOSTNAME_KEYWORDS:
            assert kw == kw.lower(), f"keyword not lowercase: {kw!r}"

    def test_failure_markers_lowercase(self):
        for m in _REVERSE_FAILURE_MARKERS:
            assert m == m.lower(), f"marker not lowercase: {m!r}"
