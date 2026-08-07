"""Reasoning-only-stop recovery. Verified live (Qwen3.5-9B): a thinking model intermittently
returns finish_reason='stop' with empty content + no tool_calls but populated
reasoning_content — it thought inside <think> and stopped without acting, so the agent loop
saw an empty final response and halted at turn 2/12. _is_reasoning_only_stop flags exactly that
dud (and nothing else) so the native model layer can retry with tool_choice='required'.
"""

from __future__ import annotations

import types

from kryon.sdk.agents.models.openai_native import (
    _is_reasoning_only_stop,
    _promote_reasoning_to_content,
)


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


# --------------------------------------------------------------------------- #
# _promote_reasoning_to_content — capable-model recovery. A capable thinking   #
# model leaves its final conclusion in reasoning_content; promoting it to      #
# content keeps the analysis out of "(el agente no produjo salida final)".     #
# --------------------------------------------------------------------------- #


def test_promotes_reasoning_when_content_empty():
    r = _resp("stop", "", "Audit summary: SPF/DMARC missing, CSP weak.", None)
    assert _promote_reasoning_to_content(r) is True
    assert r.choices[0].message.content == "Audit summary: SPF/DMARC missing, CSP weak."


def test_does_not_overwrite_existing_content():
    r = _resp("stop", "Real answer already here.", "some reasoning", None)
    assert _promote_reasoning_to_content(r) is False
    assert r.choices[0].message.content == "Real answer already here."


def test_no_promotion_when_reasoning_empty():
    r = _resp("stop", "", "", None)
    assert _promote_reasoning_to_content(r) is False
    assert r.choices[0].message.content == ""


def test_promotes_via_reasoning_field_alias():
    r = _resp("stop", "", "", None)
    r.choices[0].message = types.SimpleNamespace(content="", reasoning="alias thought", tool_calls=None)
    assert _promote_reasoning_to_content(r) is True
    assert r.choices[0].message.content == "alias thought"


def test_promotion_strips_surrounding_whitespace():
    r = _resp("stop", "   ", "  trimmed conclusion  ", None)
    assert _promote_reasoning_to_content(r) is True
    assert r.choices[0].message.content == "trimmed conclusion"


def test_promotion_malformed_response_does_not_raise():
    assert _promote_reasoning_to_content(object()) is False
    assert _promote_reasoning_to_content(types.SimpleNamespace(choices=[])) is False


# --------------------------------------------------------------------------- #
# KRYON_PRESERVE_REASONING — decouples reasoning-promotion from the full        #
# capable regime, so a good local reasoner (qwen-unc) run non-capable for       #
# latency still keeps its answer instead of losing it to an empty final_output. #
# --------------------------------------------------------------------------- #


def test_preserve_reasoning_off_by_default(monkeypatch):
    from kryon.util.env import preserve_reasoning

    monkeypatch.delenv("KRYON_PRESERVE_REASONING", raising=False)
    assert preserve_reasoning() is False


def test_preserve_reasoning_reads_flag(monkeypatch):
    from kryon.util.env import preserve_reasoning

    monkeypatch.setenv("KRYON_PRESERVE_REASONING", "true")
    assert preserve_reasoning() is True
    monkeypatch.setenv("KRYON_PRESERVE_REASONING", "0")
    assert preserve_reasoning() is False


def test_promotion_gate_enabled_by_preserve_without_capable(monkeypatch):
    """The gate that guards _promote_reasoning_to_content in _fetch_response is
    ``is_capable_model() or preserve_reasoning()``. With PRESERVE on and CAPABLE
    off, the model stays in the fast non-capable regime yet reasoning is promoted."""
    from kryon.util.env import is_capable_model, preserve_reasoning

    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    monkeypatch.setenv("KRYON_PRESERVE_REASONING", "true")

    assert is_capable_model() is False
    assert preserve_reasoning() is True
    assert (is_capable_model() or preserve_reasoning()) is True  # promotion path taken


def test_promotion_gate_off_when_both_unset(monkeypatch):
    from kryon.util.env import is_capable_model, preserve_reasoning

    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    monkeypatch.delenv("KRYON_PRESERVE_REASONING", raising=False)

    assert (is_capable_model() or preserve_reasoning()) is False  # force-tool path taken
