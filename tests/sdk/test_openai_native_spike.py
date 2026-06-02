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


def test_native_is_default_litellm_is_escape_hatch(monkeypatch):
    import kryon.agents.base as base
    from kryon.sdk.agents import OpenAIChatCompletionsModel
    from kryon.sdk.agents.models.openai_native import OpenAINativeModel

    # Default (no flags) → native.
    monkeypatch.delenv("KRYON_USE_LITELLM", raising=False)
    monkeypatch.delenv("KRYON_USE_NATIVE_OPENAI", raising=False)
    assert base.chat_model_cls() is OpenAINativeModel

    # Escape hatch → litellm-backed model.
    monkeypatch.setenv("KRYON_USE_LITELLM", "true")
    assert base.chat_model_cls() is OpenAIChatCompletionsModel


def test_native_import_does_not_load_litellm():
    """P1 invariant: importing the DEFAULT model path must NOT import litellm.

    litellm is the ``KRYON_USE_LITELLM`` escape hatch — its import + global-flag
    monkeypatching are deferred to ``_ensure_litellm_configured()``, only run by
    litellm-path methods (which the native model overrides). Runs in a FRESH
    subprocess because the test suite has litellm in sys.modules already; this
    guards against anyone re-adding a module-level ``import litellm``.
    """
    import subprocess
    import sys

    code = (
        "import sys; "
        "import kryon.sdk.agents.models.openai_native; "
        "assert 'litellm' not in sys.modules, 'litellm imported on default path'; "
        "print('CLEAN')"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "CLEAN" in result.stdout


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


async def test_native_fetch_logs_when_fix_message_list_fails(monkeypatch, caplog):
    """P2 observability: a fix_message_list repair failure on the native path is
    debug-logged (not silently swallowed) but does NOT abort the call."""
    import logging

    import kryon.util as kutil
    from kryon.sdk.agents.models.openai_native import OpenAINativeModel

    def _boom(_messages):
        raise ValueError("bad message shape")

    monkeypatch.setattr(kutil, "fix_message_list", _boom)

    create = AsyncMock(return_value=SimpleNamespace(choices=[], usage=None))
    client = MagicMock()
    client.chat.completions.create = create
    model = OpenAINativeModel(model="deepseek-chat", openai_client=client)

    with caplog.at_level(logging.DEBUG, logger="openai.agents"):
        await model._fetch_response(
            system_instructions="sys",
            input="hi",
            model_settings=_model_settings(),
            tools=[],
            output_schema=None,
            handoffs=[],
            span=None,
            tracing=SimpleNamespace(include_data=lambda: False),
            stream=False,
        )

    # The call still proceeded despite the repair failure...
    create.assert_awaited_once()
    # ...and the failure is now diagnosable instead of vanishing.
    assert "fix_message_list failed (native path)" in caplog.text


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
