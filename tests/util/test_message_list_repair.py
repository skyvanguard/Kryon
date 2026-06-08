"""Regression: fix_message_list must synthesize a tool response for an
assistant that RE-EMITS a tool_call_id already used earlier.

DeepSeek/OpenAI reject an assistant tool_calls message without a tool response
per tool_call_id ("insufficient tool messages following tool_calls"). The model
sometimes re-emits an old tool_call_id after a reflection turn; the previous
dedup logic skipped it (already in consumed_tool_ids), leaving that assistant
with no response → 400.
"""

from __future__ import annotations

from kryon.util import fix_message_list


def _asst(call_id):
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{"id": call_id, "type": "function", "function": {"name": "f", "arguments": "{}"}}],
    }


def test_reemitted_tool_call_id_gets_its_own_response():
    msgs = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "audit"},
        _asst("call_A"),
        {"role": "tool", "tool_call_id": "call_A", "content": "resp A"},
        {"role": "user", "content": "reflection nudge"},
        _asst("call_A"),  # model re-emits the SAME id, no response after it
    ]
    out = fix_message_list(msgs)
    # Every assistant-with-tool_calls must be immediately followed by a tool
    # response for each of its tool_call_ids.
    for i, m in enumerate(out):
        if m.get("role") == "assistant" and m.get("tool_calls"):
            ids = {tc["id"] for tc in m["tool_calls"]}
            following = {out[j].get("tool_call_id") for j in range(i + 1, len(out)) if out[j].get("role") == "tool"}
            assert ids <= following, f"assistant#{i} tool_calls {ids} missing responses (have {following})"


def test_multiple_reemitted_ids_all_get_responses():
    msgs = [
        {"role": "user", "content": "go"},
        _asst("c1"),
        {"role": "tool", "tool_call_id": "c1", "content": "r1"},
        _asst("c2"),
        {"role": "tool", "tool_call_id": "c2", "content": "r2"},
        {"role": "user", "content": "reflect"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{}"}},
                {"id": "c2", "type": "function", "function": {"name": "g", "arguments": "{}"}},
            ],
        },
    ]
    out = fix_message_list(msgs)
    last = max(i for i, m in enumerate(out) if m.get("role") == "assistant" and m.get("tool_calls"))
    resp_ids = {out[j].get("tool_call_id") for j in range(last + 1, len(out)) if out[j].get("role") == "tool"}
    assert {"c1", "c2"} <= resp_ids
