"""DEFAULT model: native AsyncOpenAI HTTP layer (no litellm at call time).

Selected by ``agents.base.chat_model_cls()`` for every run unless
``KRYON_USE_LITELLM=true`` restores the litellm-backed parent. Drop-in subclass
of ``OpenAIChatCompletionsModel`` that overrides ONLY the HTTP call layer —
replacing ``litellm.acompletion`` with the native ``openai`` async client. It
reuses the parent's converters, streaming loop, and response parsing untouched.

What it DROPS vs the litellm path (`OpenAIChatCompletionsModel._fetch_response`,
~780 lines, 2998-3776):
  * the per-provider branching (deepseek/claude/gemini/groq/ollama/qwen/...),
  * the ``litellm.drop_params`` toggling,
  * the ``openai/<model>`` prefix + ``custom_llm_provider`` hack,
  * the disabled litellm callbacks / ``modify_params`` reliance.

Rationale: Kryon's real runtime is 100% OpenAI-compatible (llama.cpp + DeepSeek),
so the native client with ``base_url`` handles it directly. This spike measures
how much workaround disappears. The native client also returns real
``ChatCompletion`` / ``AsyncStream`` objects — exactly what the SDK's parsing
expects (the upstream openai-agents model uses this client), so downstream is
MORE compatible, not less.

The claude/gemini ``cache_control`` block is intentionally omitted (irrelevant
for the OpenAI-compatible local/DeepSeek endpoints this targets).

NOTE: importing this module still imports ``openai_chatcompletions`` (for the
shared converters), which runs litellm's import-time monkeypatching. The native
path avoids litellm at *call* time, not *import* time — removing that import
coupling is tracked separately (P1: extract a litellm-free base module).
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import TYPE_CHECKING, Any, Literal, cast

from openai import NOT_GIVEN, AsyncStream
from openai.types.chat import ChatCompletion, ChatCompletionChunk
from openai.types.responses import Response

from ..logger import logger
from .fake_id import FAKE_RESPONSES_ID
from .openai_chatcompletions import (
    _HEADERS,
    OpenAIChatCompletionsModel,
    ToolConverter,
    _merge_history_and_converter,
    _should_force_directive_tool_choice,
)

if TYPE_CHECKING:
    from ..handoffs import Handoff
    from ..items import TResponseInputItem
    from ..tool import Tool
    from .interface import ModelTracing


# Transient-fault retry policy for the native call. A local llama.cpp server can
# answer 5xx mid-run (overload, or "Failed to parse tool call arguments" when the
# model emits a malformed tool_call); a single one used to abort engage/REPL runs.
_TRANSIENT_RETRIES = 2
_TRANSIENT_BACKOFF_S = 1.5


def _is_transient_model_error(e: Exception) -> bool:
    """True ONLY for INFRA-transient faults worth a cheap retry: HTTP 5xx from
    overload, connection/timeout blips. These clear on retry.

    The malformed-tool_call parse error is deliberately EXCLUDED: it's the model
    generating invalid JSON (deterministic at low temp), so retrying the same
    request just burns tokens without changing the outcome. That case is handled
    one layer up by the reflective_runner's nudge (which changes the input), with
    its own determinism cap — retrying it blindly here would compound into ~N×M
    wasted calls."""
    name = type(e).__name__.lower()
    msg = str(e).lower()
    if "parse tool call" in msg:  # model-deterministic, not infra-transient
        return False
    if getattr(e, "status_code", None) in (500, 502, 503, 504):
        return True
    return any(k in name for k in ("internalservererror", "apiconnectionerror", "apitimeout"))


class OpenAINativeModel(OpenAIChatCompletionsModel):
    """Same model, native HTTP layer. Only ``_fetch_response`` differs."""

    async def _fetch_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: Any,
        tools: list[Tool],
        output_schema: Any,
        handoffs: list[Handoff],
        span: Any,
        tracing: ModelTracing,
        stream: bool = False,
    ) -> ChatCompletion | tuple[Response, AsyncStream[ChatCompletionChunk]]:
        from kryon.util import fix_message_list

        # --- messages: authoritative enriched history + only converter messages
        # it doesn't already represent (P5: the Runner passes the full
        # conversation as `input` every turn AND the fork keeps it in
        # message_history; converting both and concatenating sent it TWICE). The
        # converter call is kept for its side-effects (flushing pending tool
        # calls into message_history).
        converter_messages = self._converter.items_to_messages(input, model_instance=self)
        converted_messages: list[dict] = _merge_history_and_converter(self.message_history, converter_messages)
        if system_instructions and not any(m.get("role") == "system" for m in converted_messages):
            converted_messages.insert(0, {"role": "system", "content": system_instructions})

        try:
            converted_messages = fix_message_list(converted_messages)
        except Exception as exc:  # noqa: BLE001 — repair is best-effort
            # Repair failure isn't fatal, but it's the usual cause of a later
            # provider 400 (assistant tool_calls not followed by a tool result).
            # Log at debug so it's diagnosable instead of vanishing.
            logger.debug("fix_message_list failed (native path): %s", exc)

        if tracing.include_data():
            span.span_data.input = converted_messages

        # --- tools / tool_choice / response_format (reuse parent converters) ---
        parallel_tool_calls = True if (model_settings.parallel_tool_calls and tools) else NOT_GIVEN
        tool_choice = self._converter.convert_tool_choice(model_settings.tool_choice)
        response_format = self._converter.convert_response_format(output_schema)
        converted_tools = [ToolConverter.to_openai(t) for t in tools] if tools else []
        for handoff in handoffs:
            converted_tools.append(ToolConverter.convert_handoff_tool(handoff))

        # KRYON_FORCE_TOOL_TURNS + FASE 11.Q — force tool-use for the first N LLM
        # calls of the turn (so the model chains tools instead of narrating) and on
        # a high-confidence planner directive. This lived ONLY in the litellm path,
        # so the env var was a silent no-op on the native default — exactly the path
        # deepseek-chat uses. _turn_llm_calls is incremented by the inherited
        # get_response and reset per-turn by add_to_message_history, so it's valid
        # here too.
        if converted_tools:
            _force_tool_turns = int(os.environ.get("KRYON_FORCE_TOOL_TURNS", "8"))
            if self._turn_llm_calls <= _force_tool_turns:
                tool_choice = "required"
            elif _should_force_directive_tool_choice(True, tool_choice):
                tool_choice = "required"
        self._last_effective_tool_choice = tool_choice

        agent_model = getattr(model_settings, "agent_model", None)
        # Forward reasoning_effort when set (F184 / KRYON_REASONING_EFFORT).
        # gpt-oss + DeepSeek thinking + o-series all read it; llama.cpp's gpt-oss
        # --jinja maps it to the Harmony "Reasoning: <level>" system directive.
        # The litellm path already forwards it; the native default did not, so
        # KRYON_REASONING_EFFORT was a silent no-op on the default backend.
        reasoning_effort = self._non_null_or_not_given(getattr(model_settings, "reasoning_effort", None))
        kwargs: dict[str, Any] = {
            "model": agent_model or self.model,
            "messages": converted_messages,
            "tools": converted_tools or NOT_GIVEN,
            "temperature": self._non_null_or_not_given(model_settings.temperature),
            "top_p": self._non_null_or_not_given(model_settings.top_p),
            "frequency_penalty": self._non_null_or_not_given(model_settings.frequency_penalty),
            "presence_penalty": self._non_null_or_not_given(model_settings.presence_penalty),
            "max_tokens": self._non_null_or_not_given(model_settings.max_tokens),
            "reasoning_effort": reasoning_effort,
            "tool_choice": tool_choice,
            "response_format": response_format,
            "parallel_tool_calls": parallel_tool_calls,
            "stream": stream,
            "stream_options": {"include_usage": True} if stream else NOT_GIVEN,
            "extra_headers": _HEADERS,
        }

        client = self._get_client()

        async def _create():
            """Single native call, with two recovery paths worth keeping:
            1. over-long tool_call_id → truncate all ids to 40 chars and retry once;
            2. transient server faults (5xx, a local model's malformed-tool_call
               parse error, connection blips) → short-backoff retry instead of
               aborting. A single 500 "Failed to parse tool call arguments" used to
               kill engage / REPL runs outright (the reflective_runner nudge only
               covers `kryon investigate`); this is the common adapter layer so the
               safety net reaches every call site."""
            for _attempt in range(_TRANSIENT_RETRIES + 1):
                try:
                    return await client.chat.completions.create(**kwargs)
                except Exception as e:  # noqa: BLE001
                    msg = str(e)
                    if "tool_call_id" in msg and ("maximum length" in msg or "string too long" in msg):
                        for m in kwargs.get("messages", []):
                            tcid = m.get("tool_call_id")
                            if isinstance(tcid, str) and len(tcid) > 40:
                                m["tool_call_id"] = tcid[:40]
                            for tc in m.get("tool_calls", []) or []:
                                if isinstance(tc, dict) and isinstance(tc.get("id"), str) and len(tc["id"]) > 40:
                                    tc["id"] = tc["id"][:40]
                        return await client.chat.completions.create(**kwargs)
                    if _attempt < _TRANSIENT_RETRIES and _is_transient_model_error(e):
                        await asyncio.sleep(_TRANSIENT_BACKOFF_S * (_attempt + 1))
                        continue
                    raise
            raise RuntimeError("unreachable")  # pragma: no cover

        if stream:
            stream_obj = await _create()
            response = Response(
                id=FAKE_RESPONSES_ID,
                created_at=time.time(),
                model=str(self.model),
                object="response",
                output=[],
                tool_choice="auto"
                if tool_choice is None or tool_choice == NOT_GIVEN
                else cast(Literal["auto", "required", "none"], tool_choice),
                top_p=model_settings.top_p,
                temperature=model_settings.temperature,
                tools=[],
                parallel_tool_calls=bool(parallel_tool_calls) if parallel_tool_calls is not NOT_GIVEN else False,
            )
            return response, stream_obj
        return await _create()
