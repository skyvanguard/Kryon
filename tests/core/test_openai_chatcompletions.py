from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

# Set test API key to prevent OpenAI client initialization errors
if not os.environ.get("OPENAI_API_KEY"):
    os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"


# Check if local model is available (ollama or similar)
def _check_local_model_available():
    """Check if a local model server is running."""
    try:
        import httpx

        with httpx.Client(timeout=2.0) as client:
            response = client.get("http://localhost:11434/api/tags")
            return response.status_code == 200
    except Exception:
        return False


_has_local_model = _check_local_model_available()

import httpx
import pytest
from openai import NOT_GIVEN
from openai.types.chat.chat_completion import ChatCompletion, Choice
from openai.types.chat.chat_completion_chunk import ChatCompletionChunk
from openai.types.chat.chat_completion_message import ChatCompletionMessage
from openai.types.chat.chat_completion_message_tool_call import (
    ChatCompletionMessageToolCall,
    Function,
)
from openai.types.completion_usage import CompletionUsage
from openai.types.responses import (
    Response,
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputRefusal,
    ResponseOutputText,
)

from kryon.sdk.agents import (
    ModelResponse,
    ModelSettings,
    ModelTracing,
    OpenAIChatCompletionsModel,
    OpenAIProvider,
    generation_span,
)
from kryon.sdk.agents.models.fake_id import FAKE_RESPONSES_ID

kryon_model = os.getenv("KRYON_MODEL", "qwen2.5:14b")


@pytest.mark.allow_call_model_methods
@pytest.mark.asyncio
async def test_get_response_with_text_message(monkeypatch) -> None:
    """
    When the model returns a ChatCompletionMessage with plain text content,
    `get_response` should produce a single `ResponseOutputMessage` containing
    a `ResponseOutputText` with that content, and a `Usage` populated from
    the completion's usage.
    """
    msg = ChatCompletionMessage(role="assistant", content="Hello")
    choice = Choice(index=0, finish_reason="stop", message=msg)
    chat = ChatCompletion(
        id="resp-id",
        created=0,
        model="fake",
        object="chat.completion",
        choices=[choice],
        usage=CompletionUsage(completion_tokens=5, prompt_tokens=7, total_tokens=12),
    )

    async def patched_fetch_response(self, *args, **kwargs):
        return chat

    monkeypatch.setattr(OpenAIChatCompletionsModel, "_fetch_response", patched_fetch_response)
    model = OpenAIProvider(use_responses=False).get_model(kryon_model)
    resp: ModelResponse = await model.get_response(
        system_instructions=None,
        input="",
        model_settings=ModelSettings(),
        tools=[],
        output_schema=None,
        handoffs=[],
        tracing=ModelTracing.DISABLED,
    )
    # Should have produced exactly one output message with one text part
    assert isinstance(resp, ModelResponse)
    assert len(resp.output) == 1
    assert isinstance(resp.output[0], ResponseOutputMessage)
    msg_item = resp.output[0]
    assert len(msg_item.content) == 1
    assert isinstance(msg_item.content[0], ResponseOutputText)
    assert msg_item.content[0].text == "Hello"
    # Usage should be preserved from underlying ChatCompletion.usage
    assert resp.usage.input_tokens == 7
    assert resp.usage.output_tokens == 5
    assert resp.usage.total_tokens == 12
    assert resp.referenceable_id is None


@pytest.mark.allow_call_model_methods
@pytest.mark.asyncio
async def test_get_response_with_refusal(monkeypatch) -> None:
    """
    When the model returns a ChatCompletionMessage with a `refusal` instead
    of normal `content`, `get_response` should produce a single
    `ResponseOutputMessage` containing a `ResponseOutputRefusal` part.
    """
    msg = ChatCompletionMessage(role="assistant", refusal="No thanks")
    choice = Choice(index=0, finish_reason="stop", message=msg)
    chat = ChatCompletion(
        id="resp-id",
        created=0,
        model="fake",
        object="chat.completion",
        choices=[choice],
        usage=None,
    )

    async def patched_fetch_response(self, *args, **kwargs):
        return chat

    monkeypatch.setattr(OpenAIChatCompletionsModel, "_fetch_response", patched_fetch_response)
    model = OpenAIProvider(use_responses=False).get_model(kryon_model)
    resp: ModelResponse = await model.get_response(
        system_instructions=None,
        input="",
        model_settings=ModelSettings(),
        tools=[],
        output_schema=None,
        handoffs=[],
        tracing=ModelTracing.DISABLED,
    )
    assert len(resp.output) == 1
    assert isinstance(resp.output[0], ResponseOutputMessage)
    refusal_part = resp.output[0].content[0]
    assert isinstance(refusal_part, ResponseOutputRefusal)
    assert refusal_part.refusal == "No thanks"
    # With no usage from the completion, usage defaults to zeros.
    assert resp.usage.requests == 1
    assert resp.usage.input_tokens == 6  # Updated to match current implementation
    assert resp.usage.output_tokens == 0


@pytest.mark.allow_call_model_methods
@pytest.mark.asyncio
async def test_get_response_with_tool_call(monkeypatch) -> None:
    """
    If the ChatCompletionMessage includes one or more tool_calls, `get_response`
    should append corresponding `ResponseFunctionToolCall` items after the
    assistant message item with matching name/arguments.
    """
    tool_call = ChatCompletionMessageToolCall(
        id="call-id",
        type="function",
        function=Function(name="do_thing", arguments="{'x':1}"),
    )
    msg = ChatCompletionMessage(role="assistant", content="Hi", tool_calls=[tool_call])
    choice = Choice(index=0, finish_reason="stop", message=msg)
    chat = ChatCompletion(
        id="resp-id",
        created=0,
        model="fake",
        object="chat.completion",
        choices=[choice],
        usage=None,
    )

    async def patched_fetch_response(self, *args, **kwargs):
        return chat

    monkeypatch.setattr(OpenAIChatCompletionsModel, "_fetch_response", patched_fetch_response)
    model = OpenAIProvider(use_responses=False).get_model(kryon_model)
    resp: ModelResponse = await model.get_response(
        system_instructions=None,
        input="",
        model_settings=ModelSettings(),
        tools=[],
        output_schema=None,
        handoffs=[],
        tracing=ModelTracing.DISABLED,
    )
    # Expect a message item followed by a function tool call item.
    assert len(resp.output) == 2
    assert isinstance(resp.output[0], ResponseOutputMessage)
    fn_call_item = resp.output[1]
    assert isinstance(fn_call_item, ResponseFunctionToolCall)
    assert fn_call_item.call_id == "call-id"
    assert fn_call_item.name == "do_thing"
    assert fn_call_item.arguments == "{'x':1}"


@pytest.mark.allow_call_model_methods
@pytest.mark.asyncio
async def test_get_response_parses_multi_tool_json_in_content(monkeypatch) -> None:
    """Local models without --jinja tool grammar (DeepHat-V1-7B) return
    ``tool_calls: null`` and emit the call(s) as NDJSON in ``content``. On the
    local path, ``get_response`` must recover EVERY call — the regression the
    old first-{/last-} fallback caused (it dropped all but one)."""
    import json as _json

    content = (
        '{"name": "run_nmap", "arguments": {"target": "10.10.10.5"}}\n'
        '{"name": "run_sqlmap", "arguments": {"url": "http://10.10.10.5/login?id=1"}}'
    )
    msg = ChatCompletionMessage(role="assistant", content=content, tool_calls=None)
    choice = Choice(index=0, finish_reason="stop", message=msg)
    chat = ChatCompletion(
        id="resp-id",
        created=0,
        model="fake",
        object="chat.completion",
        choices=[choice],
        usage=None,
    )

    async def patched_fetch_response(self, *args, **kwargs):
        return chat

    monkeypatch.setattr(OpenAIChatCompletionsModel, "_fetch_response", patched_fetch_response)
    model = OpenAIProvider(use_responses=False).get_model(kryon_model)
    model.is_local_llm = True  # force the local-model JSON-in-content fallback

    resp: ModelResponse = await model.get_response(
        system_instructions=None,
        input="",
        model_settings=ModelSettings(),
        tools=[],
        output_schema=None,
        handoffs=[],
        tracing=ModelTracing.DISABLED,
    )

    fn_calls = [it for it in resp.output if isinstance(it, ResponseFunctionToolCall)]
    assert [c.name for c in fn_calls] == ["run_nmap", "run_sqlmap"]
    assert _json.loads(fn_calls[1].arguments) == {"url": "http://10.10.10.5/login?id=1"}


@pytest.mark.skipif(not _has_local_model, reason="Requires local model server (ollama)")
@pytest.mark.asyncio
async def test_fetch_response_non_stream(monkeypatch) -> None:
    """
    Verify that `_fetch_response` builds the correct kwargs and passes them
    through to litellm.acompletion when not streaming.
    """
    # Isolate from OLLAMA env var so routing goes through litellm_openai path
    monkeypatch.delenv("OLLAMA", raising=False)

    msg = ChatCompletionMessage(role="assistant", content="ignored")
    choice = Choice(index=0, finish_reason="stop", message=msg)
    chat = ChatCompletion(
        id="resp-id",
        created=0,
        model="fake",
        object="chat.completion",
        choices=[choice],
    )

    # Capture kwargs passed to litellm.acompletion
    captured_kwargs: dict[str, Any] = {}

    async def fake_acompletion(**kwargs: Any) -> Any:
        captured_kwargs.update(kwargs)
        return chat

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)

    dummy_client = type(
        "_C",
        (),
        {
            "chat": type("_Ch", (), {"completions": None})(),
            "base_url": httpx.URL("http://fake"),
        },
    )()
    model = OpenAIChatCompletionsModel(model=kryon_model, openai_client=dummy_client)  # type: ignore
    model.message_history = []  # Clear any leaked state from AGENT_MANAGER

    with generation_span(disabled=True) as span:
        await model._fetch_response(
            system_instructions="sys",
            input="hi",
            model_settings=ModelSettings(),
            tools=[],
            output_schema=None,
            handoffs=[],
            span=span,
            tracing=ModelTracing.DISABLED,
            stream=False,
        )

    # Ensure expected args were passed through to litellm
    assert captured_kwargs["stream"] is False
    assert captured_kwargs["model"] == kryon_model
    assert captured_kwargs["messages"][0]["role"] == "system"
    assert captured_kwargs["messages"][0]["content"] == "sys"
    assert captured_kwargs["messages"][1]["role"] == "user"


@pytest.mark.skipif(not _has_local_model, reason="Requires local model server (ollama)")
@pytest.mark.asyncio
async def test_fetch_response_stream(monkeypatch) -> None:
    """
    When `stream=True`, `_fetch_response` should return a bare `Response`
    object along with the underlying async stream.
    """
    # Isolate from OLLAMA env var
    monkeypatch.delenv("OLLAMA", raising=False)
    monkeypatch.setenv("KRYON_STREAM", "true")

    async def event_stream() -> AsyncIterator[ChatCompletionChunk]:
        if False:  # pragma: no cover
            yield  # pragma: no cover

    # Capture kwargs passed to litellm.acompletion
    captured_kwargs: dict[str, Any] = {}

    async def fake_acompletion(**kwargs: Any) -> Any:
        captured_kwargs.update(kwargs)
        return event_stream()

    import litellm

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)

    dummy_client = type(
        "_C",
        (),
        {
            "chat": type("_Ch", (), {"completions": None})(),
            "base_url": httpx.URL("http://fake"),
        },
    )()
    model = OpenAIChatCompletionsModel(model=kryon_model, openai_client=dummy_client)  # type: ignore
    with generation_span(disabled=True) as span:
        response, stream = await model._fetch_response(
            system_instructions=None,
            input="hi",
            model_settings=ModelSettings(),
            tools=[],
            output_schema=None,
            handoffs=[],
            span=span,
            tracing=ModelTracing.DISABLED,
            stream=True,
        )
    # Check litellm was called for streaming
    assert captured_kwargs["stream"] is True
    assert captured_kwargs["stream_options"] == {"include_usage": True}
    # Response is a proper openai Response
    assert isinstance(response, Response)
    assert response.id == FAKE_RESPONSES_ID
    assert response.model == kryon_model
    assert response.object == "response"
    assert response.output == []
    # We returned the async iterator produced by our mock.
    assert hasattr(stream, "__aiter__")


@pytest.mark.allow_call_model_methods
@pytest.mark.asyncio
async def test_interaction_counter_single_turn_with_tool_calls(monkeypatch) -> None:
    """
    Test that when the LLM returns both a message and tool calls in the same turn,
    the interaction counter is incremented only once (not separately for message and tool calls).
    """
    # Create a response with both message content and tool calls
    tool_call = ChatCompletionMessageToolCall(
        id="call-id",
        type="function",
        function=Function(name="do_thing", arguments='{"x":1}'),
    )
    msg = ChatCompletionMessage(
        role="assistant",
        content="I'll help you with that. Let me use a tool.",
        tool_calls=[tool_call],
    )
    choice = Choice(index=0, finish_reason="stop", message=msg)
    chat = ChatCompletion(
        id="resp-id",
        created=0,
        model="fake",
        object="chat.completion",
        choices=[choice],
        usage=CompletionUsage(completion_tokens=10, prompt_tokens=5, total_tokens=15),
    )

    async def patched_fetch_response(self, *args, **kwargs):
        return chat

    monkeypatch.setattr(OpenAIChatCompletionsModel, "_fetch_response", patched_fetch_response)
    model = OpenAIProvider(use_responses=False).get_model(kryon_model)

    # Initial counter should be 0
    assert model.interaction_counter == 0

    # Make the request
    resp: ModelResponse = await model.get_response(
        system_instructions="You are a helpful assistant",
        input="Help me with something",
        model_settings=ModelSettings(),
        tools=[],
        output_schema=None,
        handoffs=[],
        tracing=ModelTracing.DISABLED,
    )

    # Counter should be incremented only once for the entire turn
    assert model.interaction_counter == 1

    # Verify response contains both message and tool call
    assert len(resp.output) == 2  # One message item, one tool call item
    assert isinstance(resp.output[0], ResponseOutputMessage)
    assert isinstance(resp.output[1], ResponseFunctionToolCall)

    # Make another request to ensure counter increments properly
    await model.get_response(
        system_instructions="You are a helpful assistant",
        input="Another request",
        model_settings=ModelSettings(),
        tools=[],
        output_schema=None,
        handoffs=[],
        tracing=ModelTracing.DISABLED,
    )

    # Counter should now be 2 (one increment per turn, not per item)
    assert model.interaction_counter == 2


# --- P3: local-LLM detection (rename is_ollama -> is_local_llm + unify) ---


@pytest.mark.unit
def test_detect_local_llm_env_matrix(monkeypatch):
    from kryon.sdk.agents.models.openai_chatcompletions import _detect_local_llm

    monkeypatch.delenv("KRYON_LOCAL_LLM", raising=False)
    monkeypatch.delenv("OLLAMA", raising=False)
    assert _detect_local_llm() is False

    # Canonical flag.
    monkeypatch.setenv("KRYON_LOCAL_LLM", "true")
    assert _detect_local_llm() is True

    # Explicit disable.
    monkeypatch.setenv("KRYON_LOCAL_LLM", "false")
    assert _detect_local_llm() is False

    # Deprecated OLLAMA alias still recognised.
    monkeypatch.delenv("KRYON_LOCAL_LLM", raising=False)
    monkeypatch.setenv("OLLAMA", "true")
    assert _detect_local_llm() is True


@pytest.mark.unit
def test_local_llm_flag_set_from_canonical_env(monkeypatch):
    """Regression: KRYON_LOCAL_LLM=true (no OLLAMA) sets is_local_llm True, and
    the call-time re-detect agrees — the old non-streaming path checked only the
    deprecated OLLAMA var and silently reset the flag to False mid-run."""
    from kryon.sdk.agents.models.openai_chatcompletions import (
        OpenAIChatCompletionsModel,
        _detect_local_llm,
    )

    monkeypatch.delenv("OLLAMA", raising=False)
    monkeypatch.setenv("KRYON_LOCAL_LLM", "true")

    dummy_client = type(
        "_C",
        (),
        {
            "chat": type("_Ch", (), {"completions": None})(),
            "base_url": httpx.URL("http://fake"),
        },
    )()
    model = OpenAIChatCompletionsModel(model="kryon-devstral-24b", openai_client=dummy_client)  # type: ignore

    assert model.is_local_llm is True
    # _fetch_response now re-detects via the SAME helper → no disagreement.
    assert _detect_local_llm() is True


# ---------------------------------------------------------------------------
# Tolerant local-model tool-call recovery (GLM-4 via llama.cpp emits the call as
# `<func>\n<json>` in content and repeats it instead of parsing it into tool_calls)
# ---------------------------------------------------------------------------


def test_recover_tool_call_from_repeated_content():
    from kryon.sdk.agents.models.openai_chatcompletions import _recover_tool_calls_from_content

    # The exact shape observed live: the call repeated ~20x, never parsed.
    content = 'nmap_scan\n{"target": "10.0.0.5"}' * 20
    rec = _recover_tool_calls_from_content(content, {"nmap_scan", "web_fetch_smart"})
    assert rec is not None and len(rec) == 1  # first occurrence only — drops the loop
    assert rec[0].function.name == "nmap_scan"
    import json as _json

    assert _json.loads(rec[0].function.arguments) == {"target": "10.0.0.5"}


def test_recover_ignores_unknown_tool_and_plain_text():
    from kryon.sdk.agents.models.openai_chatcompletions import _recover_tool_calls_from_content

    assert _recover_tool_calls_from_content('foo_unknown\n{"x": 1}', {"nmap_scan"}) is None
    assert _recover_tool_calls_from_content("A normal answer, no tool call here.", {"nmap_scan"}) is None
    assert _recover_tool_calls_from_content(None, {"nmap_scan"}) is None
    assert _recover_tool_calls_from_content('nmap_scan\n{"target":"x"}', set()) is None  # no tools


def test_recover_picks_first_valid_json_not_garbage():
    from kryon.sdk.agents.models.openai_chatcompletions import _recover_tool_calls_from_content

    # name followed by invalid JSON for the first match, valid for a later one
    content = 'web_fetch_smart\nnot-json-here\nweb_fetch_smart\n{"url": "http://t"}'
    rec = _recover_tool_calls_from_content(content, {"web_fetch_smart"})
    assert rec is not None and rec[0].function.name == "web_fetch_smart"
