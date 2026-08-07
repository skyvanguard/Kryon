"""F195 — env-driven throttle overrides for nmap and nuclei.

Banca-safe POC contract: when KRYON_NMAP_* / KRYON_NUCLEI_* env vars are
set, the tool wrapper layers them onto its constructed command. Explicit
caller-supplied values must still win (the env vars only fill empty
slots).
"""

from __future__ import annotations

import json
import os
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.sdk.agents import RunContextWrapper
from kryon.tools.reconnaissance.nmap import _apply_throttle_env
from kryon.tools.web.nuclei import _env_int, nuclei_scan


async def _invoke(tool, args: dict) -> str:
    # asyncio_mode = "auto" in pyproject.toml — no explicit marker needed.
    return await tool.on_invoke_tool(RunContextWrapper(None), json.dumps(args))


# ---------------------------------------------------------------------------
# nmap — _apply_throttle_env pure helper
# ---------------------------------------------------------------------------


class TestApplyThrottleEnv:
    def test_no_env_returns_input_unchanged(self, monkeypatch):
        monkeypatch.delenv("KRYON_NMAP_TIMING", raising=False)
        monkeypatch.delenv("KRYON_NMAP_MIN_RATE", raising=False)
        monkeypatch.delenv("KRYON_NMAP_MAX_PARALLELISM", raising=False)
        assert _apply_throttle_env("-sV -sC") == "-sV -sC"

    def test_timing_added_when_absent(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        out = _apply_throttle_env("-sV")
        assert "-T2" in out

    def test_timing_accepts_bare_digit(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "2")
        out = _apply_throttle_env("-sV")
        assert "-T2" in out

    def test_timing_skipped_when_caller_already_set(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        out = _apply_throttle_env("-sV -T4")
        assert "-T4" in out
        assert "-T2" not in out

    def test_min_rate_added_when_absent(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50")
        out = _apply_throttle_env("-sV")
        assert "--min-rate 50" in out

    def test_min_rate_skipped_when_caller_set_it(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50")
        out = _apply_throttle_env("-sV --min-rate 1000")
        assert "--min-rate 1000" in out
        assert "--min-rate 50" not in out

    def test_max_parallelism_added_when_absent(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "10")
        out = _apply_throttle_env("-sV")
        assert "--max-parallelism 10" in out

    def test_all_three_combined(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50")
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "10")
        out = _apply_throttle_env("-sV")
        assert "-T2" in out
        assert "--min-rate 50" in out
        assert "--max-parallelism 10" in out


# ---------------------------------------------------------------------------
# nuclei — _env_int pure helper
# ---------------------------------------------------------------------------


class TestEnvInt:
    def test_unset_returns_none(self, monkeypatch):
        monkeypatch.delenv("KRYON_NUCLEI_RATE_LIMIT", raising=False)
        assert _env_int("KRYON_NUCLEI_RATE_LIMIT") is None

    def test_empty_string_returns_none(self, monkeypatch):
        monkeypatch.setenv("KRYON_NUCLEI_RATE_LIMIT", "")
        assert _env_int("KRYON_NUCLEI_RATE_LIMIT") is None

    def test_whitespace_only_returns_none(self, monkeypatch):
        monkeypatch.setenv("KRYON_NUCLEI_RATE_LIMIT", "   ")
        assert _env_int("KRYON_NUCLEI_RATE_LIMIT") is None

    def test_valid_int_returned(self, monkeypatch):
        monkeypatch.setenv("KRYON_NUCLEI_RATE_LIMIT", "50")
        assert _env_int("KRYON_NUCLEI_RATE_LIMIT") == 50

    def test_invalid_int_returns_none(self, monkeypatch):
        monkeypatch.setenv("KRYON_NUCLEI_RATE_LIMIT", "fifty")
        assert _env_int("KRYON_NUCLEI_RATE_LIMIT") is None


# ---------------------------------------------------------------------------
# nuclei — end-to-end env override flows into the constructed command
# ---------------------------------------------------------------------------


@pytest.fixture
def captured_cmd():
    captured: dict[str, str] = {}

    def fake_run(command: str, ctf=None, timeout=None):
        captured["cmd"] = command
        return "no findings\n"

    with patch("kryon.tools.web.nuclei.run_command", side_effect=fake_run):
        yield captured


# Unique target URLs per test — bypass @cache_scan_result memoization.
class TestNucleiEnvOverride:
    async def test_env_rate_limit_replaces_default(self, monkeypatch, captured_cmd):
        monkeypatch.setenv("KRYON_NUCLEI_RATE_LIMIT", "50")
        await _invoke(nuclei_scan, {"target": "https://throttle-rl-1.invalid"})
        assert "-rl 50" in captured_cmd["cmd"]
        assert "-rl 150" not in captured_cmd["cmd"]

    async def test_env_bulk_size_replaces_default(self, monkeypatch, captured_cmd):
        monkeypatch.setenv("KRYON_NUCLEI_BULK_SIZE", "10")
        await _invoke(nuclei_scan, {"target": "https://throttle-bs-1.invalid"})
        assert "-bs 10" in captured_cmd["cmd"]

    async def test_env_concurrency_replaces_default(self, monkeypatch, captured_cmd):
        monkeypatch.setenv("KRYON_NUCLEI_CONCURRENCY", "10")
        await _invoke(nuclei_scan, {"target": "https://throttle-c-1.invalid"})
        assert "-c 10" in captured_cmd["cmd"]

    async def test_caller_explicit_value_wins_over_env(self, monkeypatch, captured_cmd):
        monkeypatch.setenv("KRYON_NUCLEI_RATE_LIMIT", "50")
        await _invoke(
            nuclei_scan,
            {"target": "https://throttle-explicit-1.invalid", "rate_limit": 200},
        )
        assert "-rl 200" in captured_cmd["cmd"]
        assert "-rl 50" not in captured_cmd["cmd"]

    async def test_no_env_keeps_default(self, monkeypatch, captured_cmd):
        monkeypatch.delenv("KRYON_NUCLEI_RATE_LIMIT", raising=False)
        monkeypatch.delenv("KRYON_NUCLEI_BULK_SIZE", raising=False)
        monkeypatch.delenv("KRYON_NUCLEI_CONCURRENCY", raising=False)
        await _invoke(nuclei_scan, {"target": "https://throttle-default-1.invalid"})
        assert "-rl 150" in captured_cmd["cmd"]
        assert "-bs 25" in captured_cmd["cmd"]
        assert "-c 25" in captured_cmd["cmd"]
