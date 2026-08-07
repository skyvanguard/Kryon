"""Tests for KryonSettings — the central config single-source-of-truth."""

from __future__ import annotations

from pathlib import Path

from kryon.config import KryonSettings, settings
from kryon.config.settings import (
    _DEFAULT_MODEL_MAX_TOKENS,
    _LARGE_WINDOW_CONTEXT_MULTIPLIER,
    resolve_context_budget,
    resolve_model_max_tokens,
)


def test_defaults_match_documented_values(monkeypatch):
    for var in (
        "KRYON_MODEL",
        "OPENAI_BASE_URL",
        "KRYON_LOCAL_LLM",
        "KRYON_USE_LITELLM",
        "KRYON_MAX_TURNS",
        "KRYON_RED_TEAM",
        "KRYON_LLM_TEMPERATURE",
    ):
        monkeypatch.delenv(var, raising=False)
    s = KryonSettings.from_env()
    assert s.model == "kryon-local"
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


# --- model_max_tokens / auto-compact (context-window resolution) -------------


def test_resolve_max_tokens_env_override_wins():
    # Explicit KRYON_MODEL_MAX_TOKENS override beats the known-model map.
    assert resolve_model_max_tokens("deepseek-v4-flash", env_override="500000") == 500000
    # …and beats an unknown model that would otherwise fall to the default.
    assert resolve_model_max_tokens("kryon-local", env_override="1000000") == 1_000_000


def test_resolve_max_tokens_known_models():
    # DeepSeek V4 Flash — the active model — has a 1M context window.
    assert resolve_model_max_tokens("deepseek-v4-flash") == 1_000_000
    assert resolve_model_max_tokens("v4-flash") == 1_000_000
    # Remote DeepSeek chat/reasoner are 128K.
    assert resolve_model_max_tokens("deepseek-reasoner") == 128_000
    assert resolve_model_max_tokens("deepseek-chat") == 128_000


def test_resolve_max_tokens_unknown_falls_back_to_default():
    # The neutral alias 'kryon-local' is deliberately NOT mapped — over-estimating
    # a swapped-in small model's context is dangerous. Falls to the safe default.
    assert resolve_model_max_tokens("kryon-local") == _DEFAULT_MODEL_MAX_TOKENS
    assert resolve_model_max_tokens("some-random-model") == _DEFAULT_MODEL_MAX_TOKENS
    assert resolve_model_max_tokens(None) == _DEFAULT_MODEL_MAX_TOKENS


def test_resolve_max_tokens_bad_override_ignored():
    assert resolve_model_max_tokens("deepseek-v4-flash", env_override="not-a-number") == 1_000_000
    assert resolve_model_max_tokens("deepseek-v4-flash", env_override="-5") == 1_000_000
    assert resolve_model_max_tokens("deepseek-v4-flash", env_override="  ") == 1_000_000


def test_settings_exposes_model_max_tokens_and_autocompact(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL", "deepseek-v4-flash")
    monkeypatch.delenv("KRYON_MODEL_MAX_TOKENS", raising=False)
    monkeypatch.delenv("KRYON_AUTO_COMPACT", raising=False)
    monkeypatch.delenv("KRYON_AUTO_COMPACT_THRESHOLD", raising=False)
    s = KryonSettings.from_env()
    assert s.model_max_tokens == 1_000_000
    assert s.auto_compact is True
    assert s.auto_compact_threshold == 0.8


def test_settings_model_max_tokens_env_override(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL", "kryon-local")
    monkeypatch.setenv("KRYON_MODEL_MAX_TOKENS", "1000000")
    s = KryonSettings.from_env()
    assert s.model_max_tokens == 1_000_000


def test_resolve_context_budget_scales_with_window():
    # Small/medium windows keep the 4B-era fixed value; a large (V4 1M) window
    # scales it up so the reflective loop isn't starved of context.
    assert resolve_context_budget(500, model_max_tokens=32_768) == 500
    assert resolve_context_budget(500, model_max_tokens=128_000) == 500
    assert resolve_context_budget(500, model_max_tokens=1_000_000) == 500 * _LARGE_WINDOW_CONTEXT_MULTIPLIER
    assert resolve_context_budget(8000, model_max_tokens=1_000_000) == 8000 * _LARGE_WINDOW_CONTEXT_MULTIPLIER


def test_resolve_context_budget_reads_settings_when_no_arg(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL_MAX_TOKENS", "1000000")
    settings(refresh=True)
    try:
        assert resolve_context_budget(500) == 500 * _LARGE_WINDOW_CONTEXT_MULTIPLIER
    finally:
        monkeypatch.delenv("KRYON_MODEL_MAX_TOKENS", raising=False)
        settings(refresh=True)
