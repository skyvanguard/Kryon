"""F199.M — auto-extend nmap-timeout cuando throttle banca-safe activo.

Regresion detectada en POC piloto Example 2026-05-18 contra .106:
nmap -T2 --top-ports 100 --min-rate 50 --max-parallelism 10 tardo
355s real para escanear un host con 2 puertos abiertos. El default
--nmap-timeout 180 cortaba el scan a la mitad → engage devolvia
"0 puertos abiertos" silenciosamente.

F199.M extiende el timeout dinamicamente segun los multipliers
documentados en _extend_timeout_for_throttle.
"""

from __future__ import annotations

import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import _extend_timeout_for_throttle


class TestNoThrottle:
    def test_unset_env_returns_unchanged(self, monkeypatch):
        monkeypatch.delenv("KRYON_NMAP_TIMING", raising=False)
        monkeypatch.delenv("KRYON_NMAP_MIN_RATE", raising=False)
        monkeypatch.delenv("KRYON_NMAP_MAX_PARALLELISM", raising=False)
        assert _extend_timeout_for_throttle(180) == 180

    def test_t4_no_multiplier(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T4")
        assert _extend_timeout_for_throttle(180) == 180

    def test_t3_no_multiplier(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T3")
        assert _extend_timeout_for_throttle(180) == 180


class TestTimingMultiplier:
    def test_t2_triples_timeout(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        # No min-rate / max-par set.
        assert _extend_timeout_for_throttle(180) == 540

    def test_t1_quadruples_timeout(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T1")
        assert _extend_timeout_for_throttle(180) == 720

    def test_t0_quadruples_timeout(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T0")
        assert _extend_timeout_for_throttle(180) == 720

    def test_bare_digit_works(self, monkeypatch):
        """User may set KRYON_NMAP_TIMING=2 instead of T2."""
        monkeypatch.setenv("KRYON_NMAP_TIMING", "2")
        assert _extend_timeout_for_throttle(180) == 540


class TestMinRateMultiplier:
    def test_low_min_rate_doubles_on_top_of_timing(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50")
        # T2 ×3, then ×2 for low min-rate → ×6
        assert _extend_timeout_for_throttle(180) == 1080

    def test_min_rate_above_50_no_multiplier(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "200")
        assert _extend_timeout_for_throttle(180) == 180

    def test_min_rate_alone_no_change(self, monkeypatch):
        """Without timing set, min-rate alone doesn't trigger the
        timing multiplier — but it should still double if ≤ 50."""
        monkeypatch.delenv("KRYON_NMAP_TIMING", raising=False)
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50")
        # multiplier starts 1.0, ×2 for min-rate = 2.0 → 360
        assert _extend_timeout_for_throttle(180) == 360


class TestMaxParallelism:
    def test_low_parallelism_adds_30s(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "10")
        assert _extend_timeout_for_throttle(180) == 210

    def test_high_parallelism_no_change(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "100")
        assert _extend_timeout_for_throttle(180) == 180


class TestExampleScenario:
    """The exact env combination from the .106 regression."""

    def test_banca_safe_full_throttle(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_TIMING", "T2")
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "50")
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "10")
        # T2 ×3 = 540, ×2 for min-rate = 1080, +30 for parallelism = 1110
        result = _extend_timeout_for_throttle(180)
        assert result == 1110
        # Sanity: above the 355s wall-clock observed against .106.
        assert result > 355, "extended timeout must cover the real-world throttled scan time"


class TestInvalidValues:
    def test_non_numeric_min_rate_ignored(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MIN_RATE", "fast")
        assert _extend_timeout_for_throttle(180) == 180

    def test_non_numeric_max_par_ignored(self, monkeypatch):
        monkeypatch.setenv("KRYON_NMAP_MAX_PARALLELISM", "high")
        assert _extend_timeout_for_throttle(180) == 180
