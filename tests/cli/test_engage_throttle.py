"""F196 — engage._build_engage_nmap_cmd respects KRYON_NMAP_* env.

The CLI's Phase 1 used to hardcode `-T4`. F196 layers the same env
overrides as F195 (which only covered the LLM function_tool path)
onto the engage CLI itself so POC operators get banca-safe throttling
end-to-end.
"""

from __future__ import annotations

import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import _build_engage_nmap_cmd


class TestEngageNmapDefaults:
    def test_no_env_keeps_legacy_T4(self, monkeypatch):
        monkeypatch.delenv("KRYON_NMAP_TIMING", raising=False)
        monkeypatch.delenv("KRYON_NMAP_MIN_RATE", raising=False)
        monkeypatch.delenv("KRYON_NMAP_MAX_PARALLELISM", raising=False)
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "-T4" in cmd
        assert "--min-rate" not in cmd
        assert "--max-parallelism" not in cmd
        assert "10.0.0.5" in cmd


class TestEngageNmapTimingOverride:
    def test_timing_env_replaces_T4(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "-T2" in cmd
        assert "-T4" not in cmd

    def test_timing_accepts_bare_digit(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "1")
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "-T1" in cmd


class TestEngageNmapRateLimit:
    def test_min_rate_env_added(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50")
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "--min-rate 50" in cmd

    def test_max_parallelism_env_added(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "10")
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "--max-parallelism 10" in cmd

    def test_all_three_combined(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50")
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "10")
        cmd = _build_engage_nmap_cmd("192.168.1.10")
        assert "-T2" in cmd
        assert "--min-rate 50" in cmd
        assert "--max-parallelism 10" in cmd
        assert "-T4" not in cmd
        assert "192.168.1.10" in cmd


class TestEngageNmapPreservedFlags:
    """Non-throttle flags must always be present regardless of env."""

    def test_pn_st_sv_always_present(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "-Pn" in cmd
        assert "-sT" in cmd
        assert "-sV" in cmd

    def test_top_ports_100_always_present(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "--top-ports 100" in cmd

    def test_xml_output_always_present(self, monkeypatch):
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "-oX -" in cmd
