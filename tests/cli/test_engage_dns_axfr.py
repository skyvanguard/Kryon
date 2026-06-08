"""F202.B — DNS zone transfer (AXFR) detection.

Companion to F202.A. AXFR exposes the complete zone records (hostnames,
A / AAAA / SRV / TXT / MX) to anyone who can speak TCP/53 to the
server. CWE-200 (info disclosure) + CWE-668 (exposure to wrong sphere).

The check:
  1. Derives candidate zones from the target's own PTR + reverse
     in-addr.arpa zone.
  2. Attempts AXFR with `dig` first, falls back to `nslookup
     -type=AXFR` (Windows-native).
  3. Counts records returned. >=3 means a real zone dump (1 SOA + at
     least 2 non-SOA), not an isolated SOA reply.
  4. Reports HIGH (high recon value but not auth bypass).
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    _AXFR_FAILURE_MARKERS,
    DiscoveredService,
    _check_dns_zone_transfer,
    _derive_dns_zone_candidates,
    _try_axfr,
)


def _svc(host: str = "172.18.201.205", port: int = 53, state: str = "open") -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state=state, service="domain", product="")


def _fake_proc(stdout: str, stderr: str = "", returncode: int = 0):
    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)

    return _run


# Sample successful AXFR output from dig (synthetic, realistic format).
_DIG_AXFR_SUCCESS = """
; <<>> DiG 9.16.1 <<>> +time=4 +tries=1 @172.18.201.205 AXFR britimp.com.py
; (1 server found)
;; global options: +cmd
britimp.com.py.		3600	IN	SOA	dc01.britimp.com.py. admin.britimp.com.py. 2026051801 900 600 86400 3600
britimp.com.py.		3600	IN	NS	dc01.britimp.com.py.
britimp.com.py.		3600	IN	NS	dc02.britimp.com.py.
britimp.com.py.		3600	IN	MX	10 mail.britimp.com.py.
britimp.com.py.		3600	IN	TXT	"v=spf1 ip4:201.x.x.x ~all"
dc01.britimp.com.py.	1200	IN	A	172.18.201.205
dc02.britimp.com.py.	1200	IN	A	172.18.201.5
mail.britimp.com.py.	1200	IN	A	172.18.201.150
britimp.com.py.		3600	IN	SOA	dc01.britimp.com.py. admin.britimp.com.py. 2026051801 900 600 86400 3600
;; XFR size: 9 records (messages 1, bytes 412)
"""

_NSLOOKUP_AXFR_REFUSED = """
Server:  dc01.britimp.com.py
Address:  172.18.201.205

*** Can't list domain britimp.com.py: Query refused
*** Transfer failed.
"""


# ---------------------------------------------------------------------------
# Positive — AXFR succeeds
# ---------------------------------------------------------------------------


class TestAxfrSuccess:
    def test_britimp_zone_transfer_succeeds(self):
        """Simulates the worst-case .205 scenario: AXFR for britimp.com.py
        returns the full zone."""
        # Patch nslookup PTR query to return the zone name, then patch
        # the AXFR attempt to return success.
        ptr_stdout = (
            "Server:  UnKnown\nAddress:  172.18.201.205\n\nName:    dc01.britimp.com.py\nAddress:  172.18.201.205\n"
        )

        call_count = {"n": 0}

        def _multi(cmd, **_kw):
            call_count["n"] += 1
            # First call = PTR lookup, return zone-bearing output
            if call_count["n"] == 1:
                return subprocess.CompletedProcess(cmd, 0, stdout=ptr_stdout, stderr="")
            # Subsequent = AXFR. First attempt (dig) succeeds.
            return subprocess.CompletedProcess(cmd, 0, stdout=_DIG_AXFR_SUCCESS, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_dns_zone_transfer(_svc())

        assert finding is not None
        assert finding.severity == "HIGH"
        assert finding.cwe == "CWE-200"
        assert finding.rule_id == "dns-axfr-allowed"
        assert "britimp.com.py" in finding.message
        # Evidence should include records from the dump
        assert "SOA" in finding.evidence or "MX" in finding.evidence

    def test_evidence_capped(self):
        """The evidence should not exceed reasonable size (no full dump
        leak into the finding object)."""
        ptr_stdout = "Name:    host.example.com\n"

        def _multi(cmd, **_kw):
            if "AXFR" not in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=ptr_stdout, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_DIG_AXFR_SUCCESS, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_dns_zone_transfer(_svc(host="1.2.3.4"))

        assert finding is not None
        assert len(finding.evidence) <= 1200


# ---------------------------------------------------------------------------
# Negative — secure / restricted configurations
# ---------------------------------------------------------------------------


class TestAxfrRestricted:
    def test_axfr_refused(self):
        """All AXFR attempts return 'Query refused' / 'Transfer failed'."""
        ptr_stdout = "Name:    dc.example.com\n"

        def _multi(cmd, **_kw):
            if "AXFR" not in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=ptr_stdout, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_NSLOOKUP_AXFR_REFUSED, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            assert _check_dns_zone_transfer(_svc()) is None

    def test_axfr_communications_error(self):
        comm_err = "; Transfer failed.\n;; communications error to 172.18.201.205#53: end of file\n"
        ptr_stdout = "Name:    dc.example.com\n"

        def _multi(cmd, **_kw):
            if "AXFR" not in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=ptr_stdout, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=comm_err, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            assert _check_dns_zone_transfer(_svc()) is None

    def test_only_soa_returned_no_flag(self):
        """A single SOA record reply (server returned the SOA but
        refused the full transfer) must NOT be flagged as AXFR success.
        The threshold is >=3 records."""
        ptr_stdout = "Name:    dc.example.com\n"
        only_soa = "example.com.	3600	IN	SOA	dc.example.com. admin.example.com. 1 900 600 86400 3600\n"

        def _multi(cmd, **_kw):
            if "AXFR" not in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=ptr_stdout, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=only_soa, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            assert _check_dns_zone_transfer(_svc()) is None


# ---------------------------------------------------------------------------
# Gate — service / port filter
# ---------------------------------------------------------------------------


class TestGate:
    def test_non_dns_port_skipped(self):
        svc = DiscoveredService(host="h", port=80, state="open", service="http", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_dns_zone_transfer(svc) is None

    def test_closed_port_skipped(self):
        svc = DiscoveredService(host="h", port=53, state="closed", service="domain", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_dns_zone_transfer(svc) is None

    def test_no_candidate_zones_no_attempt(self):
        """PTR returns nothing AND IP doesn't yield in-addr.arpa (e.g.
        non-IPv4 string) -> no AXFR attempts."""
        # Patch the PTR lookup to return nothing useful, then ensure
        # AXFR is never called. host is not 4-octet so no reverse.
        empty_stdout = ""

        def _multi(cmd, **_kw):
            if "AXFR" in cmd:
                raise AssertionError("AXFR must not be attempted when no candidates")
            return subprocess.CompletedProcess(cmd, 0, stdout=empty_stdout, stderr="")

        svc = DiscoveredService(host="notanip", port=53, state="open", service="domain", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            assert _check_dns_zone_transfer(svc) is None


# ---------------------------------------------------------------------------
# Helpers — _derive_dns_zone_candidates / _try_axfr
# ---------------------------------------------------------------------------


class TestDeriveZoneCandidates:
    def test_ptr_yields_zone(self):
        ptr_stdout = (
            "Server:  UnKnown\nAddress:  172.18.201.205\n\nName:    dc01.britimp.com.py\nAddress:  172.18.201.205\n"
        )
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(ptr_stdout)):
            zones = _derive_dns_zone_candidates("172.18.201.205")
        assert "britimp.com.py" in zones

    def test_reverse_zone_always_added_for_ipv4(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc("")):
            zones = _derive_dns_zone_candidates("172.18.201.205")
        assert "201.18.172.in-addr.arpa" in zones

    def test_non_ipv4_no_reverse(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc("")):
            zones = _derive_dns_zone_candidates("notanip")
        assert not any(".in-addr.arpa" in z for z in zones)


class TestTryAxfr:
    def test_dig_success_first(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_proc(_DIG_AXFR_SUCCESS)):
            ok, snippet = _try_axfr("172.18.201.205", "britimp.com.py")
        assert ok is True
        assert "SOA" in snippet or "NS" in snippet

    def test_dig_failure_fallback_nslookup_also_fails(self):
        with patch(
            "kryon.cli.engage.subprocess.run",
            side_effect=_fake_proc(_NSLOOKUP_AXFR_REFUSED),
        ):
            ok, snippet = _try_axfr("172.18.201.205", "britimp.com.py")
        assert ok is False
        assert snippet == ""


class TestFailureMarkerSet:
    def test_failure_markers_lowercase(self):
        """All markers must be lowercase since the comparison lowercases the haystack."""
        for marker in _AXFR_FAILURE_MARKERS:
            assert marker == marker.lower(), f"Marker not lowercase: {marker!r}"
