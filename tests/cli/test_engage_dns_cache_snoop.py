"""F202.D — DNS cache snooping detection.

Final piece of the DNS check trilogy+1 (F202.A/B/C/D). Probes a curated
list of SaaS / banking / social domains with `dig +norecurse +cd`. A
recursor that exposes its cache will return ANSWER SECTION for names
that internal users have queried recently — revealing what services
the organization consumes.

Threshold: >=2 cached hits flag MEDIUM. Single hit could be the
recursor's own forwarder warmup; two or more is a real privacy leak.
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    _DNS_SNOOP_PROBES,
    _DNS_SNOOP_THRESHOLD,
    DiscoveredService,
    _check_dns_cache_snoop,
    _try_cache_snoop,
)


def _svc(host: str = "192.0.2.205", port: int = 53, state: str = "open") -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state=state, service="domain", product="")


# Realistic dig output samples.
_DIG_CACHED_OFFICE365 = """
; <<>> DiG 9.16 <<>> +norecurse +cd @192.0.2.205 outlook.office365.com A
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;outlook.office365.com.		IN	A

;; ANSWER SECTION:
outlook.office365.com.	300	IN	CNAME	outlook.office365.com.akadns.net.
outlook.office365.com.akadns.net. 300 IN A	52.97.169.130

;; Query time: 4 msec
;; SERVER: 192.0.2.205#53
"""

_DIG_NOT_CACHED = """
; <<>> DiG 9.16 <<>> +norecurse +cd @192.0.2.205 stripe.com A
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 67890
;; flags: qr ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;stripe.com.			IN	A

;; Query time: 2 msec
;; SERVER: 192.0.2.205#53
"""

_DIG_REFUSED = """
; <<>> DiG 9.16 <<>> +norecurse +cd @192.0.2.205 instagram.com A
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 11111
;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
"""

_DIG_DIG_CACHED_BANKING = """
; <<>> DiG 9.16 <<>> +norecurse +cd @192.0.2.205 bcp.com.py A
;; ANSWER SECTION:
bcp.com.py.		300	IN	A	200.10.224.20
"""


# ---------------------------------------------------------------------------
# Positive — cache snoop succeeds
# ---------------------------------------------------------------------------


class TestCacheSnoopDetected:
    def test_two_cached_domains_flag_medium(self):
        """Example-realistic: outlook.office365.com (Microsoft 365) +
        bcp.com.py (banking) cached -> MEDIUM finding."""

        def _multi(cmd, **_kw):
            # cmd is like ["dig", ..., "@192.0.2.205", "<name>", "A"]
            name = cmd[-2]
            if name == "outlook.office365.com":
                return subprocess.CompletedProcess(cmd, 0, stdout=_DIG_CACHED_OFFICE365, stderr="")
            if name == "bcp.com.py":
                return subprocess.CompletedProcess(cmd, 0, stdout=_DIG_DIG_CACHED_BANKING, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_DIG_NOT_CACHED, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_dns_cache_snoop(_svc())

        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert finding.cwe == "CWE-200"
        assert finding.rule_id == "dns-cache-snoop"
        assert "outlook.office365.com" in finding.evidence
        assert "bcp.com.py" in finding.evidence
        assert "2" in finding.message  # at least mentions count of 2

    def test_many_cached_domains_capped_in_summary(self):
        """If many domains cached, only show first 5 in summary +
        count of the rest."""

        def _multi(cmd, **_kw):
            name = cmd[-2]
            body = f";; ANSWER SECTION:\n{name}.\t300\tIN\tA\t1.2.3.4\n"
            return subprocess.CompletedProcess(cmd, 0, stdout=body, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            finding = _check_dns_cache_snoop(_svc())

        assert finding is not None
        # All 12 domains will be hit; message should mention "more"
        assert "more" in finding.message.lower()


# ---------------------------------------------------------------------------
# Negative — threshold + secure configs
# ---------------------------------------------------------------------------


class TestThresholdAndSecure:
    def test_single_cached_below_threshold(self):
        """One cached domain alone is below threshold (2). No flag."""

        def _multi(cmd, **_kw):
            name = cmd[-2]
            if name == "outlook.office365.com":
                return subprocess.CompletedProcess(cmd, 0, stdout=_DIG_CACHED_OFFICE365, stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=_DIG_NOT_CACHED, stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi):
            assert _check_dns_cache_snoop(_svc()) is None

    def test_none_cached_no_flag(self):
        with patch(
            "kryon.cli.engage.subprocess.run",
            side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=_DIG_NOT_CACHED, stderr=""),
        ):
            assert _check_dns_cache_snoop(_svc()) is None

    def test_all_refused_no_flag(self):
        with patch(
            "kryon.cli.engage.subprocess.run",
            side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=_DIG_REFUSED, stderr=""),
        ):
            assert _check_dns_cache_snoop(_svc()) is None


# ---------------------------------------------------------------------------
# Graceful degradation — dig unavailable
# ---------------------------------------------------------------------------


class TestDigMissing:
    def test_dig_not_installed_skip_silently(self):
        """When dig is not installed (FileNotFoundError), the check
        skips silently — no finding, no exception. Critical on
        Windows where dig is not a default binary."""

        def _raise_fnf(cmd, **_kw):
            raise FileNotFoundError("dig not found")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_raise_fnf):
            assert _check_dns_cache_snoop(_svc()) is None

    def test_partial_dig_failures_count_only_successful(self):
        """If some probes hit FileNotFoundError but others succeed,
        only the succeeded ones count toward threshold."""
        calls = {"n": 0}

        def _mixed(cmd, **_kw):
            calls["n"] += 1
            if calls["n"] <= 3:
                # First 3 calls succeed with a cached answer that
                # contains the queried name (so it's counted as a hit).
                name = cmd[-2]
                body = f";; ANSWER SECTION:\n{name}.\t300\tIN\tA\t1.2.3.4\n"
                return subprocess.CompletedProcess(cmd, 0, stdout=body, stderr="")
            raise FileNotFoundError("dig vanished mid-run")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_mixed):
            finding = _check_dns_cache_snoop(_svc())

        # 3 cached hits >= threshold 2 -> flag
        assert finding is not None


# ---------------------------------------------------------------------------
# Gate — service / port filter
# ---------------------------------------------------------------------------


class TestGate:
    def test_non_dns_port_skipped(self):
        svc = DiscoveredService(host="h", port=80, state="open", service="http", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_dns_cache_snoop(svc) is None

    def test_closed_port_skipped(self):
        svc = DiscoveredService(host="h", port=53, state="closed", service="domain", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_dns_cache_snoop(svc) is None


# ---------------------------------------------------------------------------
# Helper — _try_cache_snoop
# ---------------------------------------------------------------------------


class TestTryCacheSnoop:
    def test_cached_returns_true(self):
        with patch(
            "kryon.cli.engage.subprocess.run",
            side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=_DIG_CACHED_OFFICE365, stderr=""),
        ):
            assert _try_cache_snoop("10.0.0.5", "outlook.office365.com") is True

    def test_not_cached_returns_false(self):
        with patch(
            "kryon.cli.engage.subprocess.run",
            side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=_DIG_NOT_CACHED, stderr=""),
        ):
            assert _try_cache_snoop("10.0.0.5", "stripe.com") is False

    def test_refused_returns_none(self):
        with patch(
            "kryon.cli.engage.subprocess.run",
            side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=_DIG_REFUSED, stderr=""),
        ):
            assert _try_cache_snoop("10.0.0.5", "instagram.com") is None

    def test_dig_not_installed_returns_none(self):
        def _fnf(cmd, **_kw):
            raise FileNotFoundError

        with patch("kryon.cli.engage.subprocess.run", side_effect=_fnf):
            assert _try_cache_snoop("10.0.0.5", "stripe.com") is None


# ---------------------------------------------------------------------------
# Probe list sanity — ensure curated list is non-trivial
# ---------------------------------------------------------------------------


class TestProbeListSanity:
    def test_probes_include_microsoft_365(self):
        assert any("office365" in p or "microsoftonline" in p for p in _DNS_SNOOP_PROBES)

    def test_probes_include_paraguay_banking(self):
        assert any(".com.py" in p for p in _DNS_SNOOP_PROBES)

    def test_threshold_is_at_least_two(self):
        """Single hit must NOT be enough — too noisy. >=2."""
        assert _DNS_SNOOP_THRESHOLD >= 2

    def test_probes_no_duplicates(self):
        assert len(_DNS_SNOOP_PROBES) == len(set(_DNS_SNOOP_PROBES))
