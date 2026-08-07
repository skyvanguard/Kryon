"""Default sampling temperature is capability-gated.

Regression (G8): temperature defaulted to 0.0 (greedy) for every run, which kills
exploration for an agentic engagement — a capable model repeats one path instead of
varying enumeration/hypotheses."""

from __future__ import annotations

from kryon.sdk.agents.run import _default_temperature


def test_default_temperature_greedy_for_4b(monkeypatch):
    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    assert _default_temperature() == 0.0


def test_default_temperature_explores_for_capable_model(monkeypatch):
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    assert _default_temperature() == 0.4
