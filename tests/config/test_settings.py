"""Tests for KryonSettings — the central config single-source-of-truth."""

from __future__ import annotations

from pathlib import Path

from kryon.config import KryonSettings, settings


def test_defaults_match_documented_values(monkeypatch):
    for var in (
        "KRYON_MODEL", "OPENAI_BASE_URL", "KRYON_LOCAL_LLM", "KRYON_USE_LITELLM",
        "KRYON_MAX_TURNS", "KRYON_RED_TEAM", "KRYON_LLM_TEMPERATURE",
    ):
        monkeypatch.delenv(var, raising=False)
    s = KryonSettings.from_env()
    assert s.model == "Kryon-MOE-35B"
    assert s.openai_base_url is None
    assert s.local_llm is False
    assert s.use_litellm is False  # native model is the default
    assert s.unified is True
    assert s.max_turns == 50
    assert s.red_team is False
    assert s.llm_temperature is None  # → run-loop default


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL", "deepseek-chat")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.deepseek.com/v1")
    monkeypatch.setenv("KRYON_USE_LITELLM", "true")
    monkeypatch.setenv("KRYON_MAX_TURNS", "8")
    monkeypatch.setenv("KRYON_LLM_TEMPERATURE", "0.3")
    monkeypatch.setenv("KRYON_RED_TEAM", "1")
    s = KryonSettings.from_env()
    assert s.model == "deepseek-chat"
    assert s.openai_base_url == "https://api.deepseek.com/v1"
    assert s.use_litellm is True
    assert s.max_turns == 8
    assert s.llm_temperature == 0.3
    assert s.red_team is True


def test_bad_int_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("KRYON_MAX_TURNS", "not-a-number")
    assert KryonSettings.from_env().max_turns == 50


def test_redacted_dict_masks_api_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-supersecret-123")
    d = KryonSettings.from_env().redacted_dict()
    assert d["openai_api_key"] == "***set***"
    assert "supersecret" not in str(d)
    # Paths are stringified for safe printing.
    assert isinstance(d["home_dir"], str)


def test_settings_cache_and_refresh(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL", "model-a")
    first = settings(refresh=True)
    assert first.model == "model-a"
    monkeypatch.setenv("KRYON_MODEL", "model-b")
    assert settings().model == "model-a"  # cached
    assert settings(refresh=True).model == "model-b"  # re-read


def test_home_dir_expanded(monkeypatch):
    monkeypatch.delenv("KRYON_HOME", raising=False)
    s = KryonSettings.from_env()
    assert "~" not in str(s.home_dir)
    assert isinstance(s.home_dir, Path)
