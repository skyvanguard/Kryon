"""F202.C — DNS CHAOS class info disclosure detection.

Companion to F202.A and F202.B. BIND / Unbound / PowerDNS expose debug
data through CHAOS-class TXT queries by default (must be explicitly
suppressed). Microsoft DNS does NOT respond to CHAOS class so this
check only fires against Linux DNS engines.

Severity:
  - MEDIUM when hostname.bind / id.server leaks (internal naming
    recon payload).
  - LOW when only version.bind / version.server leaks (still useful
    for CVE matching but less impactful).
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    DiscoveredService,
    _check_dns_chaos_leak,
    _DNS_CHAOS_FAILURE_MARKERS,
    _try_chaos_query,
)


def _svc(host: str = "172.18.201.205", port: int = 53, state: str = "open") -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state=state, service="domain", product="")


def _fake_proc(stdout: str, stderr: str = "", returncode: int = 0):
    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)

    return _run


# Sample CHAOS responses
_VERSION_BIND_LEAK = (
    "Server:  ns01.example.com\n"
    "Address:  10.0.0.5\n"
    "\n"
    'version.bind   text = "9.18.24-1ubuntu1-Ubuntu"\n'
)

_HOSTNAME_BIND_LEAK = (
    "Server:  ns01.example.com\n"
    "Address:  10.0.0.5\n"
    "\n"
    'hostname.bind  text = "ns01.example.com"\n'
)

_ID_SERVER_LEAK = (
    'id.server  text = "anycast-pop-fra-3"\n'
)

_VERSION_SERVER_LEAK = (
    'version.server text = "Unbound 1.13.2"\n'
)

_CHAOS_REFUSED = (
    "Server:  ms-dns.example.com\n"
    "Address:  172.18.201.205\n"
    "\n"
    "*** ms-dns.example.com can't find version.bind: Query refused\n"
)

_CHAOS_NXDOMAIN = "*** Non-existent domain\n"


# ---------------------------------------------------------------------------
# Positive — version-only (LOW)
# ---------------------------------------------------------------------------


class TestVersionLeakLow:
    def test_version_bind_only_is_low(self):
        """A BIND server leaking only version.bind -> severity LOW."""

        def _multi(cmd, **_kw):
            # Match the probe name in the command and return only for
            # version.bind, NXDOMAIN for the rest.
            if "version.bind" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=_VERSION_BIND_LEAK, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_CHAOS_NXDOMAIN, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_dns_chaos_leak(_svc(host="10.0.0.5"))

        assert finding is not None
        assert finding.severity == "LOW"
        assert finding.cwe == "CWE-200"
        assert finding.rule_id == "dns-chaos-leak"
        assert "version.bind" in finding.message
        assert "9.18.24" in finding.evidence

    def test_version_server_only_is_low(self):
        def _multi(cmd, **_kw):
            if "version.server" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=_VERSION_SERVER_LEAK, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_CHAOS_NXDOMAIN, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_dns_chaos_leak(_svc(host="10.0.0.6"))

        assert finding is not None
        assert finding.severity == "LOW"
        assert "Unbound" in finding.evidence


# ---------------------------------------------------------------------------
# Positive — hostname / id leaks (MEDIUM)
# ---------------------------------------------------------------------------


class TestHostnameLeakMedium:
    def test_hostname_bind_promotes_to_medium(self):
        def _multi(cmd, **_kw):
            if "hostname.bind" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=_HOSTNAME_BIND_LEAK, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_CHAOS_NXDOMAIN, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_dns_chaos_leak(_svc(host="10.0.0.5"))

        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert "hostname.bind" in finding.message
        assert "ns01.example.com" in finding.evidence

    def test_id_server_promotes_to_medium(self):
        def _multi(cmd, **_kw):
            if "id.server" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=_ID_SERVER_LEAK, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_CHAOS_NXDOMAIN, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_dns_chaos_leak(_svc(host="10.0.0.5"))

        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert "anycast-pop-fra-3" in finding.evidence

    def test_version_plus_hostname_combined_is_medium(self):
        """If both version AND hostname leak, severity is MEDIUM (the
        more impactful of the two wins)."""

        def _multi(cmd, **_kw):
            if "version.bind" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=_VERSION_BIND_LEAK, stderr="")
            if "hostname.bind" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=_HOSTNAME_BIND_LEAK, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_CHAOS_NXDOMAIN, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_dns_chaos_leak(_svc(host="10.0.0.5"))

        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert "version.bind" in finding.message
        assert "hostname.bind" in finding.message


# ---------------------------------------------------------------------------
# Negative — secure / restricted configurations
# ---------------------------------------------------------------------------


class TestSecureConfigurations:
    def test_all_chaos_refused(self):
        """The .205 case: Microsoft DNS refuses CHAOS queries -> no leak."""
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(_CHAOS_REFUSED)):
            assert _check_dns_chaos_leak(_svc()) is None

    def test_all_chaos_nxdomain(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(_CHAOS_NXDOMAIN)):
            assert _check_dns_chaos_leak(_svc()) is None

    def test_chaos_timeout(self):
        with patch(
            "kryon.cli.engage.subprocess.run",
            side_effect=_fake_proc("DNS request timed out.\n"),
        ):
            assert _check_dns_chaos_leak(_svc()) is None

    def test_chaos_empty_value(self):
        """BIND with `version "";` returns CHAOS response but the TXT
        value is empty -> no flag."""
        empty_leak = 'version.bind   text = ""\n'
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(empty_leak)):
            assert _check_dns_chaos_leak(_svc()) is None


# ---------------------------------------------------------------------------
# Gate — service / port filter
# ---------------------------------------------------------------------------


class TestGate:
    def test_non_dns_port_skipped(self):
        svc = DiscoveredService(host="h", port=80, state="open", service="http", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_dns_chaos_leak(svc) is None

    def test_closed_port_skipped(self):
        svc = DiscoveredService(host="h", port=53, state="closed", service="domain", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_dns_chaos_leak(svc) is None


# ---------------------------------------------------------------------------
# Helper — _try_chaos_query
# ---------------------------------------------------------------------------


class TestTryChaosQuery:
    def test_parses_version_text(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(_VERSION_BIND_LEAK)):
            value = _try_chaos_query("10.0.0.5", "version.bind")
        assert value == "9.18.24-1ubuntu1-Ubuntu"

    def test_refused_returns_none(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(_CHAOS_REFUSED)):
            assert _try_chaos_query("10.0.0.5", "version.bind") is None

    def test_empty_value_returns_none(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc('text = ""')):
            assert _try_chaos_query("10.0.0.5", "version.bind") is None


class TestFailureMarkerSet:
    def test_all_markers_lowercase(self):
        for marker in _DNS_CHAOS_FAILURE_MARKERS:
            assert marker == marker.lower(), f"Marker not lowercase: {marker!r}"
