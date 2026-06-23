"""Reasoning-only-stop recovery. Verified live (Qwen3.5-9B): a thinking model intermittently
returns finish_reason='stop' with empty content + no tool_calls but populated
reasoning_content — it thought inside <think> and stopped without acting, so the agent loop
saw an empty final response and halted at turn 2/12. _is_reasoning_only_stop flags exactly that
dud (and nothing else) so the native model layer can retry with tool_choice='required'.
"""

from __future__ import annotations

import types

from kryon.sdk.agents.models.openai_native import _is_reasoning_only_stop


def _resp(finish: str, content: str, reasoning: str, tool_calls=None):
    msg = types.SimpleNamespace(content=content, reasoning_content=reasoning, tool_calls=tool_calls)
    ch = types.SimpleNamespace(finish_reason=finish, message=msg)
    return types.SimpleNamespace(choices=[ch])


def test_flags_the_reasoning_only_stop_dud():
    # The exact shape captured live from Qwen3.5-9B.
    assert _is_reasoning_only_stop(_resp("stop", "", "the user wants me to act...", None)) is True


def test_flags_the_overthinking_length_dud():
    # Second shape seen live: Qwen over-thought 6.5K chars and hit the generation cap
    # (finish_reason="length") before emitting a tool call. Must also be recovered.
    assert _is_reasoning_only_stop(_resp("length", "", "x" * 6571, None)) is True


def test_ignores_healthy_tool_call_response():
    assert _is_reasoning_only_stop(_resp("tool_calls", "", "reasoning", [object()])) is False


def test_ignores_legitimate_text_final():
    # A real final answer has content — not a dud, must not be retried into a forced tool call.
    assert _is_reasoning_only_stop(_resp("stop", "Here is the summary of findings.", "r", None)) is False


def test_ignores_empty_stop_without_reasoning():
    # finish_reason stop with nothing at all is not the thinking-model quirk.
    assert _is_reasoning_only_stop(_resp("stop", "", "", None)) is False


def test_handles_reasoning_field_alias():
    # Some providers expose the field as `reasoning` instead of `reasoning_content`.
    r = _resp("stop", "", "", None)
    r.choices[0].message = types.SimpleNamespace(content="", reasoning="thought", tool_calls=None)
    assert _is_reasoning_only_stop(r) is True


def test_no_choices_is_safe():
    assert _is_reasoning_only_stop(types.SimpleNamespace(choices=[])) is False


def test_malformed_response_does_not_raise():
    assert _is_reasoning_only_stop(object()) is False
