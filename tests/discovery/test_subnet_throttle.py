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


def _flag_value(cmd: list[str], flag: str) -> str:
    """Return the argv element following `flag` (argv form, post shell=False hardening)."""
    return cmd[cmd.index(flag) + 1]


class TestSubnetSweepDefaults:
    def test_no_env_keeps_legacy_T4(self, monkeypatch):
        monkeypatch.delenv("KRYON_NMAP_TIMING", raising=False)
        monkeypatch.delenv("KRYON_NMAP_MIN_RATE", raising=False)
        monkeypatch.delenv("KRYON_NMAP_MAX_PARALLELISM", raising=False)
        cmd = _build_subnet_sweep_cmd("10.0.0.0/24")
        assert cmd[:3] == ["nmap", "-sn", "-T4"]
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
        assert _flag_value(cmd, "--min-rate") == "50"

    def test_max_parallelism_added(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "10")
        cmd = _build_subnet_sweep_cmd("10.0.0.0/24")
        assert _flag_value(cmd, "--max-parallelism") == "10"

    def test_non_numeric_throttle_env_is_rejected(self, monkeypatch):
        # Security: a non-numeric (injection) value must be dropped, not interpolated.
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50; rm -rf x")
        monkeypatch.setenv("KRYON_NMAP_TIMING", "2;evil")
        cmd = _build_subnet_sweep_cmd("10.0.0.0/24")
        assert "--min-rate" not in cmd  # malicious value dropped
        assert "-T4" in cmd  # malicious timing → safe default
        assert all("rm -rf" not in part for part in cmd)

    def test_all_three_combined(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50")
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "10")
        cmd = _build_subnet_sweep_cmd("192.168.10.0/24")
        assert "-T2" in cmd
        assert _flag_value(cmd, "--min-rate") == "50"
        assert _flag_value(cmd, "--max-parallelism") == "10"
        assert "192.168.10.0/24" in cmd


class TestSubnetSweepSafety:
    """The sweep MUST always be -sn (ping-only). Throttle env should
    never accidentally turn it into a port scan."""

    def test_sn_always_present(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        cmd = _build_subnet_sweep_cmd("10.0.0.0/24")
        assert "-sn" in cmd

    def test_cidr_passed_as_argv_not_shell(self):
        # The command is now an argv list run with shell=False, so a malicious CIDR is a
        # single inert argv element (nmap rejects it) — no shell parses it.
        cmd = _build_subnet_sweep_cmd("10.0.0.0/24; rm -rf /")
        assert isinstance(cmd, list)
        assert "10.0.0.0/24; rm -rf /" in cmd  # one literal element, harmless without a shell
