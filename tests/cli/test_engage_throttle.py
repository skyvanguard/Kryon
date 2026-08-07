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
        # F202.S: cmd is now list[str], not str
        assert isinstance(cmd, list)
        assert "-T4" in cmd
        assert "--min-rate" not in cmd
        assert "--max-parallelism" not in cmd
        assert "10.0.0.5" in cmd

    def test_default_scans_top_1000_not_100(self, monkeypatch):
        # T3-A3: top-100 missed redis/mongo/winrm/app-ports where the foothold lives.
        monkeypatch.delenv("KRYON_NMAP_TOP_PORTS", raising=False)
        monkeypatch.delenv("KRYON_NMAP_FULL", raising=False)
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "1000" in cmd
        assert "100" not in cmd

    def test_top_ports_env_override(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TOP_PORTS", "2000")
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "2000" in cmd

    def test_nmap_full_uses_all_ports(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_FULL", "1")
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "-p-" in cmd
        assert "--top-ports" not in cmd

    def test_explicit_ports_still_win(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_FULL", "1")
        cmd = _build_engage_nmap_cmd("10.0.0.5", ports="22,80,443")
        assert "-p" in cmd
        assert "22,80,443" in cmd
        assert "-p-" not in cmd


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
        # F202.S: flag + value in separate list items (argv style)
        assert "--min-rate" in cmd
        assert "50" in cmd
        assert cmd[cmd.index("--min-rate") + 1] == "50"

    def test_max_parallelism_env_added(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "10")
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "--max-parallelism" in cmd
        assert cmd[cmd.index("--max-parallelism") + 1] == "10"

    def test_all_three_combined(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50")
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "10")
        cmd = _build_engage_nmap_cmd("192.168.1.10")
        assert "-T2" in cmd
        assert "--min-rate" in cmd
        assert "50" in cmd
        assert "--max-parallelism" in cmd
        assert "10" in cmd
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

    def test_top_ports_present_by_default(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        monkeypatch.delenv("KRYON_NMAP_TOP_PORTS", raising=False)
        monkeypatch.delenv("KRYON_NMAP_FULL", raising=False)
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "--top-ports" in cmd
        assert "1000" in cmd  # T3-A3: default raised from 100 to 1000

    def test_xml_output_always_present(self, monkeypatch):
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert "-oX" in cmd
        assert "-" in cmd


class TestF202SShellSafety:
    """F202.S — argv list eliminates shell injection risk."""

    def test_returns_list_not_string(self, monkeypatch):
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert isinstance(cmd, list)
        assert all(isinstance(item, str) for item in cmd)

    def test_malicious_env_not_interpreted_as_shell(self, monkeypatch):
        """If env var contains shell metacharacters, they're preserved
        literally in argv (no shell interpretation possible)."""
        monkeypatch.setenv("KRYON_NMAP_TIMING", "2; curl evil")
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        # The literal string ends up as a list item, not as separate
        # commands — argv passing prevents shell injection.
        joined = " ".join(cmd)
        # Argv ensures the env value lands in a single argv slot
        # (or is parsed safely), not as a chained command.
        assert any("curl evil" in item or "2; curl evil" in item for item in cmd) or "evil" not in joined


class TestURLTargetExtraction:
    """Discovery must feed nmap a bare host/IP, never a URL — a URL fails
    to resolve ('0 puertos'). Regression: engage vs http://juice_shop:3000."""

    def test_url_target_stripped_to_host(self):
        cmd = _build_engage_nmap_cmd("http://juice_shop:3000")
        assert cmd[-1] == "juice_shop"  # bare host, not the URL
        assert "http://juice_shop:3000" not in cmd

    def test_url_explicit_port_folded_into_scan(self):
        cmd = _build_engage_nmap_cmd("http://juice_shop:3000")
        # the URL's :3000 is scanned even though --top-ports would be the default
        assert "-p" in cmd and "3000" in cmd

    def test_bare_host_unchanged(self):
        cmd = _build_engage_nmap_cmd("10.0.0.5")
        assert cmd[-1] == "10.0.0.5"

    def test_host_port_pair_folds_port(self):
        cmd = _build_engage_nmap_cmd("10.0.0.5:8080")
        assert cmd[-1] == "10.0.0.5" and "8080" in cmd


class TestServesHTTP:
    """Web checks must run on non-canonical web ports even when nmap
    misclassifies them. Regression: Juice Shop :3000 shows as 'ppp'."""

    def _svc(self, port, service):
        from kryon.cli.engage import DiscoveredService

        return DiscoveredService(host="h", port=port, state="open", service=service, product="", version="")

    def test_noncanonical_web_port_is_http(self):
        from kryon.cli.engage import _serves_http

        assert _serves_http(self._svc(3000, "ppp")) is True  # the bug case

    def test_canonical_http_is_http(self):
        from kryon.cli.engage import _serves_http

        assert _serves_http(self._svc(80, "http")) is True

    def test_ssh_is_not_http(self):
        from kryon.cli.engage import _serves_http

        assert _serves_http(self._svc(22, "ssh")) is False
