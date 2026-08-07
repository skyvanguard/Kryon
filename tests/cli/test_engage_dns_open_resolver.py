"""F202.A — DNS open resolver detection.

Regression test for the gap detected in the Example POC pilot 2026-05-18
against .205 (DC example.com.py). Manual probe `nslookup google.com
192.0.2.205` resolved to public Google IPs (142.251.128.78 +
IPv6 2800:3f0:4002:801::200e), proving the DC accepts recursive
queries from arbitrary clients reachable on the data plane. If the
perimeter firewall does not block UDP/53 from internet, this is a
DNS amplification DDoS reflector.

The check flags MEDIUM (not HIGH) because from inside the network we
cannot prove external reachability. The remediation walks the operator
through DNS-level recursion ACLs AND perimeter firewall review.
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    DiscoveredService,
    _check_dns_open_resolver,
    _is_external_ipv4,
)


def _svc(host: str = "192.0.2.205", port: int = 53, state: str = "open") -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state=state, service="domain", product="")


def _fake_nslookup(stdout: str, stderr: str = "", returncode: int = 0):
    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)

    return _run


# ---------------------------------------------------------------------------
# Positive — open resolver detected
# ---------------------------------------------------------------------------


class TestOpenResolverDetected:
    def test_example_h205_scenario(self):
        """The exact .205 case: recursive query for google.com succeeds."""
        stdout = (
            "Server:  UnKnown\n"
            "Address:  192.0.2.205\n"
            "\n"
            "Non-authoritative answer:\n"
            "Name:    google.com\n"
            "Addresses:  142.251.128.78\n"
            "          2800:3f0:4002:801::200e\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_nslookup(stdout)):
            finding = _check_dns_open_resolver(_svc())
        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert finding.cwe == "CWE-406"
        assert finding.rule_id == "dns-open-resolver"
        assert "142.251.128.78" in finding.evidence
        assert "amplificador" in finding.remediation.lower()

    def test_resolves_multiple_external(self):
        stdout = (
            "Server:  dns01.example\n"
            "Address:  192.0.2.5\n"
            "\n"
            "Name:    google.com\n"
            "Addresses:  142.251.128.78\n"
            "          142.251.128.100\n"
            "          142.251.128.101\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_nslookup(stdout)):
            finding = _check_dns_open_resolver(_svc(host="192.0.2.5"))
        assert finding is not None
        # First external IP must be in message
        assert "142.251.128.78" in finding.message


# ---------------------------------------------------------------------------
# Negative — secure / restricted configurations
# ---------------------------------------------------------------------------


class TestSecureConfigurations:
    def test_recursion_refused(self):
        stdout = (
            "Server:  internal-dns.example\n"
            "Address:  192.0.2.205\n"
            "\n"
            "*** internal-dns.example can't find google.com: Query refused\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_nslookup(stdout)):
            assert _check_dns_open_resolver(_svc()) is None

    def test_nxdomain(self):
        stdout = "*** Non-existent domain\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_nslookup(stdout)):
            assert _check_dns_open_resolver(_svc()) is None

    def test_server_failed(self):
        stdout = "*** Server failed\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_nslookup(stdout)):
            assert _check_dns_open_resolver(_svc()) is None

    def test_timeout(self):
        stdout = "DNS request timed out.\n  timeout was 2 seconds.\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_nslookup(stdout)):
            assert _check_dns_open_resolver(_svc()) is None

    def test_no_response(self):
        stdout = "*** No response from server\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_nslookup(stdout)):
            assert _check_dns_open_resolver(_svc()) is None

    def test_only_rfc1918_ips_returned(self):
        """If nslookup output only contains the target IP (echoed back
        as 'Address: <target>') and no external IPs, do NOT flag.
        This is the typical 'recursion disabled, query refused but
        the server still echoes its own address' scenario."""
        stdout = (
            "Server:  UnKnown\nAddress:  192.0.2.205\n\n*** UnKnown can't find google.com: Non-existent domain\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_nslookup(stdout)):
            assert _check_dns_open_resolver(_svc()) is None


# ---------------------------------------------------------------------------
# Gate — service / port filter
# ---------------------------------------------------------------------------


class TestGate:
    def test_non_dns_port_skipped(self):
        svc = DiscoveredService(host="h", port=80, state="open", service="http", product="")
        # subprocess.run should NOT be called when port != 53.
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_dns_open_resolver(svc) is None

    def test_closed_port_skipped(self):
        svc = DiscoveredService(host="h", port=53, state="closed", service="domain", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_dns_open_resolver(svc) is None


# ---------------------------------------------------------------------------
# Helper — _is_external_ipv4
# ---------------------------------------------------------------------------


class TestIsExternalIpv4:
    def test_public_google_ip_is_external(self):
        assert _is_external_ipv4("142.251.128.78", "192.0.2.205") is True

    def test_rfc1918_10_is_not_external(self):
        assert _is_external_ipv4("10.0.0.5", "192.0.2.205") is False

    def test_rfc1918_172_is_not_external(self):
        assert _is_external_ipv4("172.20.0.5", "192.0.2.205") is False
        assert _is_external_ipv4("172.16.0.1", "192.0.2.205") is False
        assert _is_external_ipv4("172.31.255.254", "192.0.2.205") is False

    def test_172_outside_rfc1918_range_is_external(self):
        """172.15.x.x and 172.32.x.x are NOT RFC1918 — they're public
        IP space (USDoD / various). The check must not treat them as
        internal just because they start with 172."""
        assert _is_external_ipv4("172.15.0.1", "192.0.2.205") is True
        assert _is_external_ipv4("172.32.0.1", "192.0.2.205") is True

    def test_192_168_is_not_external(self):
        assert _is_external_ipv4("192.168.1.1", "192.0.2.205") is False

    def test_loopback_is_not_external(self):
        assert _is_external_ipv4("127.0.0.1", "192.0.2.205") is False

    def test_link_local_is_not_external(self):
        assert _is_external_ipv4("169.254.1.5", "192.0.2.205") is False

    def test_target_self_is_not_external(self):
        """When nslookup echoes back the target IP itself as 'Address:'
        line — don't count it as an external resolution."""
        assert _is_external_ipv4("192.0.2.205", "192.0.2.205") is False

    def test_target_self_even_if_public_is_not_external(self):
        """Edge case: a publicly-routable DNS server echoing itself."""
        assert _is_external_ipv4("8.8.8.8", "8.8.8.8") is False
