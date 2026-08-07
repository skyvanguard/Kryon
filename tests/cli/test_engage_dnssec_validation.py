"""F202.E — DNSSEC validation status check.

Quinto check de la pentalogia DNS. Probe a `dnssec-failed.org` (Verisign-
maintained domain con firma DELIBERADAMENTE rota). Si el resolver
valida DNSSEC, debe retornar SERVFAIL. Si retorna IP, validacion esta
apagada -> vulnerable a cache poisoning + MITM injection (CWE-345).
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    _DNSSEC_INCONCLUSIVE_MARKERS,
    _DNSSEC_TEST_DOMAIN,
    _DNSSEC_VALID_MARKERS,
    DiscoveredService,
    _check_dnssec_validation,
)


def _svc(host: str = "192.0.2.205", port: int = 53, state: str = "open") -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state=state, service="domain", product="")


def _fake_proc(stdout: str, stderr: str = "", returncode: int = 0):
    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)

    return _run


# Sample nslookup outputs.
_NSLOOKUP_NOT_VALIDATING = (
    "Server:  UnKnown\n"
    "Address:  192.0.2.205\n"
    "\n"
    "Non-authoritative answer:\n"
    "Name:    dnssec-failed.org\n"
    "Address:  68.87.85.234\n"
)

_NSLOOKUP_VALIDATING_SERVFAIL = (
    "Server:  UnKnown\nAddress:  192.0.2.205\n\n*** UnKnown can't find dnssec-failed.org: Server failed\n"
)

_NSLOOKUP_TIMEOUT = "Server:  UnKnown\nAddress:  192.0.2.205\n\nDNS request timed out.\n    timeout was 2 seconds.\n"


# ---------------------------------------------------------------------------
# Positive — DNSSEC NOT validating (the BAD outcome)
# ---------------------------------------------------------------------------


class TestDnssecNotValidating:
    def test_recursor_returns_ip_for_broken_zone(self):
        """Worst case: the recursor returned a real IP for
        dnssec-failed.org — validation is off."""
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(_NSLOOKUP_NOT_VALIDATING)):
            finding = _check_dnssec_validation(_svc())
        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert finding.cwe == "CWE-345"
        assert finding.rule_id == "dnssec-validation-disabled"
        assert "dnssec-failed.org" in finding.message
        assert "68.87.85.234" in finding.evidence
        assert "cache poisoning" in finding.message.lower()

    def test_remediation_mentions_engines(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(_NSLOOKUP_NOT_VALIDATING)):
            finding = _check_dnssec_validation(_svc())
        assert finding is not None
        assert "BIND" in finding.remediation
        assert "Unbound" in finding.remediation
        assert "Microsoft DNS" in finding.remediation


# ---------------------------------------------------------------------------
# Negative — DNSSEC validating (the GOOD outcome)
# ---------------------------------------------------------------------------


class TestDnssecValidating:
    def test_servfail_response_means_validation_works(self):
        """The exact GOOD scenario: nslookup says 'Server failed'."""
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(_NSLOOKUP_VALIDATING_SERVFAIL)):
            assert _check_dnssec_validation(_svc()) is None

    def test_explicit_servfail_string(self):
        out = "*** UnKnown can't find dnssec-failed.org: SERVFAIL\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(out)):
            assert _check_dnssec_validation(_svc()) is None


# ---------------------------------------------------------------------------
# Inconclusive — probe couldn't be performed cleanly
# ---------------------------------------------------------------------------


class TestInconclusive:
    def test_timeout_no_finding(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(_NSLOOKUP_TIMEOUT)):
            assert _check_dnssec_validation(_svc()) is None

    def test_no_response_no_finding(self):
        out = "*** No response from server\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(out)):
            assert _check_dnssec_validation(_svc()) is None

    def test_no_ips_returned_no_finding(self):
        """Server replied but didn't return ANY IPs at all. Treated
        as inconclusive (not a flag — we'd be guessing)."""
        out = "Server:  UnKnown\nAddress:  192.0.2.205\n\n"
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(out)):
            assert _check_dnssec_validation(_svc()) is None

    def test_only_loopback_ip_no_finding(self):
        """The server's own IP in the address line is not a real
        resolution of the broken-DNSSEC zone."""
        out = "Server:  UnKnown\nAddress:  127.0.0.1\n\n"
        svc = DiscoveredService(host="127.0.0.1", port=53, state="open", service="domain", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(out)):
            assert _check_dnssec_validation(svc) is None


# ---------------------------------------------------------------------------
# Gate — service / port filter
# ---------------------------------------------------------------------------


class TestGate:
    def test_non_dns_port_skipped(self):
        svc = DiscoveredService(host="h", port=80, state="open", service="http", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_dnssec_validation(svc) is None

    def test_closed_port_skipped(self):
        svc = DiscoveredService(host="h", port=53, state="closed", service="domain", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_dnssec_validation(svc) is None


# ---------------------------------------------------------------------------
# Marker set sanity
# ---------------------------------------------------------------------------


class TestMarkerSets:
    def test_valid_markers_lowercase(self):
        for m in _DNSSEC_VALID_MARKERS:
            assert m == m.lower(), f"valid marker not lowercase: {m!r}"

    def test_inconclusive_markers_lowercase(self):
        for m in _DNSSEC_INCONCLUSIVE_MARKERS:
            assert m == m.lower(), f"inconclusive marker not lowercase: {m!r}"

    def test_test_domain_is_verisign_broken(self):
        """Sanity check — make sure we're hitting the canonical
        broken-DNSSEC test zone."""
        assert _DNSSEC_TEST_DOMAIN == "dnssec-failed.org"
