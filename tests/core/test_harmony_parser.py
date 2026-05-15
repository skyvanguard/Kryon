"""F162 — OpenAI Harmony format tool-call parser.

gpt-oss-20b emits tool calls using OpenAI's Harmony chat format, which
diverges from the OpenAI Chat Completions standard. Kryon's SDK expects
``tool_calls: [{...}]`` arrays, so we parse Harmony strings into that
shape before they reach the run loop.

Harmony tool-call structure (canonical form):

    <|start|>assistant<|channel|>commentary to=NAMESPACE.FUNC \
        <|constrain|>json<|message|>{...args...}<|call|>

Variant emitted by gpt-oss-20b on Ollama (informal short form):

    <|start|>assistant<|channel|>analysis to=container.exec code\
    <|message|>{...args...}<|call|>

These tests pin both the canonical and informal variants seen in the
F161 Juice Shop bench output. The parser must return ``None`` for
plain assistant text (no tool call), so the existing fallback paths
(JSON-in-content) downstream of this parser still apply.
"""

from __future__ import annotations

import json

import pytest

from kryon.sdk.agents.models.harmony_parser import parse_harmony_tool_calls


# ---------------------------------------------------------------------------
# Detection: no Harmony tokens → None
# ---------------------------------------------------------------------------


def test_plain_text_returns_none():
    assert parse_harmony_tool_calls("Hola, soy una respuesta normal.") is None


def test_empty_string_returns_none():
    assert parse_harmony_tool_calls("") is None


def test_whitespace_only_returns_none():
    assert parse_harmony_tool_calls("   \n\t  ") is None


def test_text_with_irrelevant_pipes_returns_none():
    # Random pipes that look like Harmony tokens but aren't
    assert parse_harmony_tool_calls("Some text with | pipes | inside.") is None


# ---------------------------------------------------------------------------
# Canonical Harmony tool call (commentary channel + <|constrain|>json)
# ---------------------------------------------------------------------------


def test_canonical_commentary_tool_call():
    harmony = (
        "<|start|>assistant<|channel|>commentary to=functions.get_weather "
        '<|constrain|>json<|message|>{"location":"SF"}<|call|>'
    )
    result = parse_harmony_tool_calls(harmony)
    assert result is not None
    assert len(result) == 1
    tc = result[0]
    assert tc["type"] == "function"
    assert tc["function"]["name"] == "get_weather"
    assert json.loads(tc["function"]["arguments"]) == {"location": "SF"}
    assert tc["id"].startswith("call_")


# ---------------------------------------------------------------------------
# F161 informal variant: analysis channel + bare "code" content type
# ---------------------------------------------------------------------------


def test_f161_container_exec_short_form():
    """The exact variant we saw in the Juice Shop F161 bench."""
    harmony = (
        "<|start|>assistant<|channel|>analysis to=container.exec code"
        '<|message|>{"cmd":["bash","-lc","which nuclei"],"timeout":30}<|call|>'
    )
    result = parse_harmony_tool_calls(harmony)
    assert result is not None
    assert len(result) == 1
    tc = result[0]
    # Built-in container.exec is namespace-stripped to just "exec".
    assert tc["function"]["name"] == "exec"
    args = json.loads(tc["function"]["arguments"])
    assert args["cmd"] == ["bash", "-lc", "which nuclei"]
    assert args["timeout"] == 30


# ---------------------------------------------------------------------------
# Multiple tool calls in one response
# ---------------------------------------------------------------------------


def test_multiple_tool_calls_in_sequence():
    harmony = (
        "<|start|>assistant<|channel|>commentary to=functions.nuclei_scan "
        '<|constrain|>json<|message|>{"target":"http://x"}<|call|>'
        "<|start|>assistant<|channel|>commentary to=functions.whatweb_scan "
        '<|constrain|>json<|message|>{"target":"http://x"}<|call|>'
    )
    result = parse_harmony_tool_calls(harmony)
    assert result is not None
    assert len(result) == 2
    assert result[0]["function"]["name"] == "nuclei_scan"
    assert result[1]["function"]["name"] == "whatweb_scan"
    # IDs are unique
    assert result[0]["id"] != result[1]["id"]


# ---------------------------------------------------------------------------
# Reasoning (analysis channel without to=) + tool call → only the tool call
# ---------------------------------------------------------------------------


def test_reasoning_before_tool_call_only_returns_tool_call():
    """gpt-oss emits CoT in the analysis channel before invoking tools.
    The CoT should NOT be returned as a tool call — only the actual
    invocation should make it through."""
    harmony = (
        "<|start|>assistant<|channel|>analysis"
        "<|message|>I need to fingerprint the host first. Let me run whatweb.<|end|>"
        "<|start|>assistant<|channel|>commentary to=functions.whatweb_scan "
        '<|constrain|>json<|message|>{"target":"http://juice_shop:3000"}<|call|>'
    )
    result = parse_harmony_tool_calls(harmony)
    assert result is not None
    assert len(result) == 1
    assert result[0]["function"]["name"] == "whatweb_scan"


# ---------------------------------------------------------------------------
# Final channel (assistant message to user) → no tool calls
# ---------------------------------------------------------------------------


def test_final_channel_returns_none():
    harmony = (
        "<|start|>assistant<|channel|>final"
        "<|message|>I found 3 vulnerabilities. Report attached.<|return|>"
    )
    assert parse_harmony_tool_calls(harmony) is None


# ---------------------------------------------------------------------------
# Namespace handling
# ---------------------------------------------------------------------------


def test_functions_namespace_stripped():
    """``functions.X`` → name = ``X``."""
    harmony = (
        "<|start|>assistant<|channel|>commentary to=functions.run_sqlmap "
        '<|constrain|>json<|message|>{"url":"http://t/q?id=1"}<|call|>'
    )
    result = parse_harmony_tool_calls(harmony)
    assert result is not None
    assert result[0]["function"]["name"] == "run_sqlmap"


def test_dotted_namespace_uses_last_segment():
    """For built-ins like ``browser.search``, name = ``search``."""
    harmony = (
        "<|start|>assistant<|channel|>analysis to=browser.search code"
        '<|message|>{"query":"sqli juice shop"}<|call|>'
    )
    result = parse_harmony_tool_calls(harmony)
    assert result is not None
    assert result[0]["function"]["name"] == "search"


def test_bare_function_name_no_namespace():
    """Some Ollama variants drop the namespace entirely."""
    harmony = (
        "<|start|>assistant<|channel|>commentary to=nuclei_scan "
        '<|constrain|>json<|message|>{"target":"x"}<|call|>'
    )
    result = parse_harmony_tool_calls(harmony)
    assert result is not None
    assert result[0]["function"]["name"] == "nuclei_scan"


# ---------------------------------------------------------------------------
# Tolerance for malformed JSON
# ---------------------------------------------------------------------------


def test_malformed_json_args_kept_as_string():
    """If the JSON args don't parse, keep raw arguments — the SDK retries
    will surface the schema error to the model so it can self-correct."""
    harmony = (
        "<|start|>assistant<|channel|>commentary to=functions.x "
        "<|constrain|>json<|message|>{not-valid-json<|call|>"
    )
    result = parse_harmony_tool_calls(harmony)
    assert result is not None
    assert result[0]["function"]["name"] == "x"
    # Arguments preserved as-is so downstream sees the error
    assert "{not-valid-json" in result[0]["function"]["arguments"]


def test_json_args_with_newlines_and_whitespace():
    harmony = (
        "<|start|>assistant<|channel|>commentary to=functions.scan "
        "<|constrain|>json<|message|>{\n"
        '  "target": "http://x",\n'
        '  "deep": true\n'
        "}<|call|>"
    )
    result = parse_harmony_tool_calls(harmony)
    assert result is not None
    args = json.loads(result[0]["function"]["arguments"])
    assert args == {"target": "http://x", "deep": True}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_partial_harmony_without_closing_call_returns_none():
    """If the tool call is truncated (no <|call|> terminator), the parser
    refuses to guess — the SDK retry path picks it up instead."""
    harmony = (
        "<|start|>assistant<|channel|>commentary to=functions.x "
        '<|constrain|>json<|message|>{"target":"x"'
    )
    assert parse_harmony_tool_calls(harmony) is None


def test_tool_call_in_middle_of_long_response():
    """The tool call may be embedded in a longer transcript."""
    harmony = (
        "Some prefix garbage.\n"
        "<|start|>assistant<|channel|>commentary to=functions.scan "
        '<|constrain|>json<|message|>{"x":1}<|call|>'
        "trailing noise"
    )
    result = parse_harmony_tool_calls(harmony)
    assert result is not None
    assert result[0]["function"]["name"] == "scan"


def test_call_id_is_unique_per_invocation():
    harmony = (
        "<|start|>assistant<|channel|>commentary to=functions.x "
        '<|constrain|>json<|message|>{"a":1}<|call|>'
    )
    r1 = parse_harmony_tool_calls(harmony)
    r2 = parse_harmony_tool_calls(harmony)
    assert r1 is not None and r2 is not None
    assert r1[0]["id"] != r2[0]["id"]


def test_arguments_serialized_as_string_not_dict():
    """OpenAI ChatCompletion tool_calls expect arguments as a JSON STRING,
    not a parsed dict. The SDK parses the string later."""
    harmony = (
        "<|start|>assistant<|channel|>commentary to=functions.x "
        '<|constrain|>json<|message|>{"a":1}<|call|>'
    )
    result = parse_harmony_tool_calls(harmony)
    assert result is not None
    assert isinstance(result[0]["function"]["arguments"], str)
