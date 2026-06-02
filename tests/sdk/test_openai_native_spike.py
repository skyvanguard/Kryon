"""Spike tests: native AsyncOpenAI model (KRYON_USE_NATIVE_OPENAI).

Proves the native path calls the openai client directly with CLEAN kwargs —
no litellm `openai/<model>` prefix, no custom_llm_provider, no provider
branching — while reusing the parent's converters. The mock client captures
the call so nothing hits the network.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest


def test_flag_selects_native_model(monkeypatch):
    import kryon.agents.base as base

    monkeypatch.delenv("KRYON_USE_NATIVE_OPENAI", raising=False)
    from kryon.sdk.agents import OpenAIChatCompletionsModel

    assert base.chat_model_cls() is OpenAIChatCompletionsModel

    monkeypatch.setenv("KRYON_USE_NATIVE_OPENAI", "true")
    from kryon.sdk.agents.models.openai_native import OpenAINativeModel

    assert base.chat_model_cls() is OpenAINativeModel


def _model_settings():
    return SimpleNamespace(
        temperature=0.3,
        top_p=None,
        frequency_penalty=None,
        presence_penalty=None,
        max_tokens=None,
        tool_choice=None,
        parallel_tool_calls=False,
        store=None,
        agent_model=None,
        reasoning_effort=None,
    )


async def test_native_fetch_calls_client_with_clean_kwargs():
    from kryon.sdk.agents.models.openai_native import OpenAINativeModel

    # Mock client whose chat.completions.create captures kwargs.
    create = AsyncMock(return_value=SimpleNamespace(choices=[], usage=None))
    client = MagicMock()
    client.chat.completions.create = create

    model = OpenAINativeModel(model="deepseek-chat", openai_client=client)

    await model._fetch_response(
        system_instructions="you are kryon",
        input="audit https://t",
        model_settings=_model_settings(),
        tools=[],
        output_schema=None,
        handoffs=[],
        span=None,
        tracing=SimpleNamespace(include_data=lambda: False),
        stream=False,
    )

    create.assert_awaited_once()
    kwargs = create.await_args.kwargs

    # The native path must NOT mangle the model name the way litellm needs.
    assert kwargs["model"] == "deepseek-chat"
    assert not str(kwargs["model"]).startswith("openai/")
    # No litellm-isms leaked into the native call.
    assert "custom_llm_provider" not in kwargs
    assert "api_base" not in kwargs
    # System + user message present (converters reused).
    roles = [m.get("role") for m in kwargs["messages"]]
    assert "system" in roles
    assert kwargs["stream"] is False


async def test_native_fetch_stream_returns_response_tuple():
    from kryon.sdk.agents.models.openai_native import OpenAINativeModel

    fake_stream = object()
    create = AsyncMock(return_value=fake_stream)
    client = MagicMock()
    client.chat.completions.create = create

    model = OpenAINativeModel(model="Kryon-MOE-35B", openai_client=client)
    result = await model._fetch_response(
        system_instructions=None,
        input="hi",
        model_settings=_model_settings(),
        tools=[],
        output_schema=None,
        handoffs=[],
        span=None,
        tracing=SimpleNamespace(include_data=lambda: False),
        stream=True,
    )
    assert isinstance(result, tuple)
    response, stream_obj = result
    assert stream_obj is fake_stream
    assert response.object == "response"
    assert create.await_args.kwargs["stream"] is True
