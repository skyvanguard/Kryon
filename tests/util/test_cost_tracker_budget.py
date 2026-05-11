"""F85.B — Verify KRYON_PRICE_LIMIT is parsed correctly and the runtime
default has shifted from unlimited to 5 USD per session.

The old default of float("inf") let a stuck agent run consume an entire
API key. The new default caps each run at 5 USD; operators can opt out
explicitly via KRYON_PRICE_LIMIT=inf or raise the cap to any value.
"""

from __future__ import annotations

import importlib

import pytest


def _reload_cost_tracker():
    """Force a reload so the module-level _parse_price_limit() picks up
    the current env state."""
    import kryon.util.cost_tracker as ct

    importlib.reload(ct)
    return ct


def test_default_price_limit_is_five_dollars(monkeypatch):
    monkeypatch.delenv("KRYON_PRICE_LIMIT", raising=False)
    ct = _reload_cost_tracker()
    assert ct._parse_price_limit() == 5.0


def test_explicit_inf_disables_cap(monkeypatch):
    monkeypatch.setenv("KRYON_PRICE_LIMIT", "inf")
    ct = _reload_cost_tracker()
    assert ct._parse_price_limit() == float("inf")


def test_unlimited_alias_disables_cap(monkeypatch):
    monkeypatch.setenv("KRYON_PRICE_LIMIT", "unlimited")
    ct = _reload_cost_tracker()
    assert ct._parse_price_limit() == float("inf")


def test_numeric_override(monkeypatch):
    monkeypatch.setenv("KRYON_PRICE_LIMIT", "12.5")
    ct = _reload_cost_tracker()
    assert ct._parse_price_limit() == 12.5


def test_garbage_value_falls_back_to_five(monkeypatch):
    monkeypatch.setenv("KRYON_PRICE_LIMIT", "not-a-number")
    ct = _reload_cost_tracker()
    assert ct._parse_price_limit() == 5.0


def test_check_price_limit_raises_when_exceeded(monkeypatch):
    monkeypatch.setenv("KRYON_PRICE_LIMIT", "1.0")
    ct = _reload_cost_tracker()
    tracker = ct.CostTracker()
    tracker.session_total_cost = 0.7

    with pytest.raises(RuntimeError, match="KRYON_PRICE_LIMIT exceeded"):
        tracker.check_price_limit(0.5)  # 0.7 + 0.5 > 1.0


def test_check_price_limit_silent_below_cap(monkeypatch):
    monkeypatch.setenv("KRYON_PRICE_LIMIT", "1.0")
    ct = _reload_cost_tracker()
    tracker = ct.CostTracker()
    tracker.session_total_cost = 0.3

    # 0.3 + 0.5 = 0.8 ≤ 1.0 — must not raise
    tracker.check_price_limit(0.5)


def test_sdk_run_module_defaults_match(monkeypatch):
    """The SDK runner exports DEFAULT_MAX_TURNS / DEFAULT_PRICE_LIMIT as
    discoverable constants. F85.B shifted them from inf to 40/5.0; if
    that regresses, this test catches it before a deploy."""
    monkeypatch.delenv("KRYON_MAX_TURNS", raising=False)
    monkeypatch.delenv("KRYON_PRICE_LIMIT", raising=False)
    import kryon.sdk.agents.run as run_module

    importlib.reload(run_module)
    assert run_module.DEFAULT_MAX_TURNS == 40
    assert run_module.DEFAULT_PRICE_LIMIT == 5.0
