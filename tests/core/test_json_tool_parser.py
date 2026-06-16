"""JSON-in-content tool-call parser.

Local GGUF chat templates that don't wire ``--jinja`` tool grammar (e.g.
mradermacher's DeepHat-V1-7B) return ``tool_calls: null`` and write the call(s)
into ``content`` as raw JSON. These tests pin the exact shapes captured live
from DeepHat-V1-7B so the parser keeps recovering them — especially the
multi-step NDJSON case the legacy first-``{``/last-``}`` fallback dropped.
"""

from __future__ import annotations

import json

from kryon.sdk.agents.models.json_tool_parser import parse_json_tool_calls

# ---------------------------------------------------------------------------
# Detection: no tool call → None (so upstream/downstream paths still apply)
# ---------------------------------------------------------------------------


def test_plain_text_returns_none():
    assert parse_json_tool_calls("Just a normal assistant answer, no tools.") is None


def test_empty_returns_none():
    assert parse_json_tool_calls("") is None
    assert parse_json_tool_calls("   \n  ") is None


def test_json_without_name_and_arguments_returns_none():
    # Incidental JSON the model is describing — not an invocation.
    assert parse_json_tool_calls('{"foo": 1, "bar": 2}') is None
    assert parse_json_tool_calls('{"name": "x"}') is None  # missing arguments


# ---------------------------------------------------------------------------
# Golden cases captured live from DeepHat-V1-7B (Q6_K, llama.cpp --jinja)
# ---------------------------------------------------------------------------


def test_single_tool_call():
    content = '{"name": "run_nmap", "arguments": {"target": "10.10.10.5"}}'
    calls = parse_json_tool_calls(content)
    assert calls is not None
    assert len(calls) == 1
    assert calls[0]["type"] == "function"
    assert calls[0]["function"]["name"] == "run_nmap"
    assert json.loads(calls[0]["function"]["arguments"]) == {"target": "10.10.10.5"}
    assert calls[0]["id"].startswith("call_")


def test_multi_step_ndjson_recovers_both_calls():
    # The regression the legacy fallback caused: two objects newline-separated.
    content = (
        '{"name": "run_nmap", "arguments": {"target": "10.10.10.5"}}\n'
        '{"name": "run_sqlmap", "arguments": {"url": "http://10.10.10.5/login?id=1"}}'
    )
    calls = parse_json_tool_calls(content)
    assert calls is not None
    assert [c["function"]["name"] for c in calls] == ["run_nmap", "run_sqlmap"]
    assert json.loads(calls[1]["function"]["arguments"]) == {"url": "http://10.10.10.5/login?id=1"}


def test_braces_inside_string_values():
    content = '{"name": "run_sqlmap", "arguments": {"url": "http://t.com/p?q=a&b={x}", "data": "user=admin&pass=p{1}"}}'
    calls = parse_json_tool_calls(content)
    assert calls is not None
    assert len(calls) == 1
    args = json.loads(calls[0]["function"]["arguments"])
    assert args["url"] == "http://t.com/p?q=a&b={x}"
    assert args["data"] == "user=admin&pass=p{1}"


# ---------------------------------------------------------------------------
# Tolerance: wrappers and prose around the JSON
# ---------------------------------------------------------------------------


def test_tool_call_tags_are_tolerated():
    content = '<tool_call>\n{"name": "run_nmap", "arguments": {"target": "10.0.0.1"}}\n</tool_call>'
    calls = parse_json_tool_calls(content)
    assert calls is not None
    assert calls[0]["function"]["name"] == "run_nmap"


def test_prose_before_json():
    content = 'I will scan the host now.\n{"name": "run_nmap", "arguments": {"target": "1.2.3.4"}}'
    calls = parse_json_tool_calls(content)
    assert calls is not None
    assert len(calls) == 1
    assert calls[0]["function"]["name"] == "run_nmap"


def test_markdown_fenced_json():
    content = '```json\n{"name": "run_nmap", "arguments": {"target": "9.9.9.9"}}\n```'
    calls = parse_json_tool_calls(content)
    assert calls is not None
    assert calls[0]["function"]["name"] == "run_nmap"


# ---------------------------------------------------------------------------
# Argument normalization
# ---------------------------------------------------------------------------


def test_arguments_string_is_normalized_to_json_string():
    # Some models emit arguments already as a JSON string.
    content = '{"name": "run_nmap", "arguments": "{\\"target\\": \\"5.5.5.5\\"}"}'
    calls = parse_json_tool_calls(content)
    assert calls is not None
    assert json.loads(calls[0]["function"]["arguments"]) == {"target": "5.5.5.5"}


def test_spurious_ctf_argument_is_stripped():
    content = '{"name": "run_nmap", "arguments": {"target": "5.5.5.5", "ctf": true}}'
    calls = parse_json_tool_calls(content)
    assert calls is not None
    args = json.loads(calls[0]["function"]["arguments"])
    assert "ctf" not in args
    assert args == {"target": "5.5.5.5"}
