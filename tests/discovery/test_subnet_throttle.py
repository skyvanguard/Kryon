"""F196 — discover_subnet respects KRYON_NMAP_* env.

Subnet sweep used to hardcode `-T4`. F196 honors KRYON_NMAP_TIMING /
_MIN_RATE / _MAX_PARALLELISM so POC operators get throttled discovery
in business hours. Default behaviour unchanged when env is unset.
"""

from __future__ import annotations

import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.discovery.assets import _build_subnet_sweep_cmd


class TestSubnetSweepDefaults:
    def test_no_env_keeps_legacy_T4(self, monkeypatch):
        monkeypatch.delenv("KRYON_NMAP_TIMING", raising=False)
        monkeypatch.delenv("KRYON_NMAP_MIN_RATE", raising=False)
        monkeypatch.delenv("KRYON_NMAP_MAX_PARALLELISM", raising=False)
        cmd = _build_subnet_sweep_cmd("10.0.0.0/24")
        assert "nmap -sn -T4" in cmd
        assert "10.0.0.0/24" in cmd
        assert "--min-rate" not in cmd
        assert "--max-parallelism" not in cmd


class TestSubnetSweepThrottle:
    def test_timing_env_replaces_T4(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        cmd = _build_subnet_sweep_cmd("10.0.0.0/24")
        assert "-T2" in cmd
        assert "-T4" not in cmd

    def test_min_rate_added(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50")
        cmd = _build_subnet_sweep_cmd("10.0.0.0/24")
        assert "--min-rate 50" in cmd

    def test_max_parallelism_added(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "10")
        cmd = _build_subnet_sweep_cmd("10.0.0.0/24")
        assert "--max-parallelism 10" in cmd

    def test_all_three_combined(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50")
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "10")
        cmd = _build_subnet_sweep_cmd("192.168.10.0/24")
        assert "-T2" in cmd
        assert "--min-rate 50" in cmd
        assert "--max-parallelism 10" in cmd
        assert "192.168.10.0/24" in cmd


class TestSubnetSweepSafety:
    """The sweep MUST always be -sn (ping-only). Throttle env should
    never accidentally turn it into a port scan."""

    def test_sn_always_present(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        cmd = _build_subnet_sweep_cmd("10.0.0.0/24")
        assert "-sn" in cmd

    def test_cidr_is_shell_quoted(self):
        cmd = _build_subnet_sweep_cmd("10.0.0.0/24")
        # The CIDR string ends up at the end of the command, quoted via
        # shlex.quote. For a plain CIDR with no spaces / metacharacters,
        # shlex.quote returns the string unchanged — but the assertion
        # below catches a regression where shell metacharacters could
        # be injected through a malicious CIDR-looking input.
        cmd_injection = _build_subnet_sweep_cmd("10.0.0.0/24; rm -rf /")
        assert "; rm -rf /" not in cmd_injection or "'" in cmd_injection
