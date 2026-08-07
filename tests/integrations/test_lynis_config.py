"""Lynis env config — fire gate + suggestions toggle."""

from __future__ import annotations

from kryon.integrations.lynis.config import include_suggestions, is_lynis_enabled


def test_fire_gate_default_off(monkeypatch):
    monkeypatch.delenv("KRYON_LYNIS_FIRE", raising=False)
    assert is_lynis_enabled() is False


def test_fire_gate_on(monkeypatch):
    monkeypatch.setenv("KRYON_LYNIS_FIRE", "yes")
    assert is_lynis_enabled() is True


def test_suggestions_default_on(monkeypatch):
    monkeypatch.delenv("KRYON_LYNIS_SUGGESTIONS", raising=False)
    assert include_suggestions() is True


def test_suggestions_off(monkeypatch):
    monkeypatch.setenv("KRYON_LYNIS_SUGGESTIONS", "false")
    assert include_suggestions() is False
