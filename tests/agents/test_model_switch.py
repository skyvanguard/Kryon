"""Layer #5 — the DeepSeek switch is clean, verified, and fail-fast.

The recall engine = the hardened harness + a capable model. The harness is done;
this pins the model swap so flipping to DeepSeek is one safe step: routing is
correct and a misconfigured cloud run is caught before it wastes money.
"""

from __future__ import annotations

import pytest

from kryon.agents.base import (
    _needs_litellm_for_reasoning,
    chat_model_cls,
    is_cloud_model,
    validate_model_config,
)

# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model,litellm",
    [
        ("kryon-devstral-24b", False),  # local → native
        ("deepseek-chat", False),  # V3 chat → native
        ("gpt-4o", False),  # plain OpenAI-compat → native
        ("deepseek-reasoner", False),  # thinking → native too (native round-trips reasoning_content)
        ("deepseek-v4-thinking", False),
    ],
)
def test_routing(monkeypatch, model, litellm):
    monkeypatch.setenv("KRYON_MODEL", model)
    monkeypatch.delenv("KRYON_USE_LITELLM", raising=False)
    cls = chat_model_cls()
    assert (cls.__name__ == "OpenAIChatCompletionsModel") is litellm


def test_native_round_trips_reasoning_content():
    """deepseek-reasoner works on the native path: the assistant's reasoning_content
    survives the full native message pipeline (merge → fix_message_list → the openai
    client's wire serialization), so it's echoed back next turn and the API doesn't
    400. This is what let reasoner drop off the litellm-forced route."""
    from openai._utils import maybe_transform
    from openai.types.chat.completion_create_params import CompletionCreateParamsNonStreaming

    from kryon.sdk.agents.models.openai_chatcompletions import _merge_history_and_converter
    from kryon.util import fix_message_list

    hist = [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "ok", "reasoning_content": "CHAIN-OF-THOUGHT"},
        {"role": "user", "content": "next"},
    ]
    merged = _merge_history_and_converter(hist, [])
    fixed = fix_message_list(merged)
    body = maybe_transform({"model": "deepseek-reasoner", "messages": fixed}, CompletionCreateParamsNonStreaming)
    asst = [m for m in body["messages"] if m.get("role") == "assistant"]
    assert asst and asst[0].get("reasoning_content") == "CHAIN-OF-THOUGHT"


def test_use_litellm_escape_hatch(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL", "deepseek-chat")
    monkeypatch.setenv("KRYON_USE_LITELLM", "true")
    assert chat_model_cls().__name__ == "OpenAIChatCompletionsModel"


def test_needs_litellm_helper():
    assert _needs_litellm_for_reasoning("deepseek-reasoner") is True
    assert _needs_litellm_for_reasoning("deepseek-chat") is False
    assert _needs_litellm_for_reasoning("kryon-devstral-24b") is False


# ---------------------------------------------------------------------------
# Cloud detection + fail-fast validation
# ---------------------------------------------------------------------------


def test_is_cloud_model():
    assert is_cloud_model("deepseek-chat")
    assert is_cloud_model("gpt-4o")
    assert is_cloud_model("claude-sonnet-4-6")
    assert not is_cloud_model("kryon-devstral-24b")
    # A local alias whose GGUF name carries a cloud-ish token is NOT cloud.
    assert not is_cloud_model("kryon-gpt-oss")
    assert not is_cloud_model("kryon-local")


def test_local_model_config_is_ok(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL", "kryon-devstral-24b")
    monkeypatch.setenv("OPENAI_API_KEY", "llama")
    ok, issues = validate_model_config()
    assert ok and issues == []


def test_cloud_model_without_key_flags(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL", "deepseek-chat")
    monkeypatch.setenv("OPENAI_API_KEY", "llama")  # placeholder
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.deepseek.com")
    monkeypatch.setenv("KRYON_LOCAL_LLM", "false")
    ok, issues = validate_model_config()
    assert ok is False
    assert any("OPENAI_API_KEY" in i for i in issues)


def test_deepseek_wrong_base_url_flags(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL", "deepseek-chat")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-realkey123")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://llama-server:8080/v1")  # local, not DeepSeek
    monkeypatch.setenv("KRYON_LOCAL_LLM", "false")
    ok, issues = validate_model_config()
    assert ok is False
    assert any("deepseek.com" in i.lower() for i in issues)


def test_cloud_model_with_local_llm_flag_flags(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL", "deepseek-chat")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-realkey123")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.deepseek.com")
    monkeypatch.setenv("KRYON_LOCAL_LLM", "true")  # wrong for a cloud model
    ok, issues = validate_model_config()
    assert ok is False
    assert any("KRYON_LOCAL_LLM" in i for i in issues)


def test_well_configured_deepseek_passes(monkeypatch):
    monkeypatch.setenv("KRYON_MODEL", "deepseek-chat")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-realkey123")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.deepseek.com")
    monkeypatch.setenv("KRYON_LOCAL_LLM", "false")
    ok, issues = validate_model_config()
    assert ok and issues == []
