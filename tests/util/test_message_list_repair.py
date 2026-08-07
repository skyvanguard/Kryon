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


# ---------------------------------------------------------------------------
# Role alternation for strict templates (Mistral / Devstral)
# ---------------------------------------------------------------------------


def _no_illegal_user(out):
    """No `user` may directly follow a `tool` or another `user`."""
    roles = [m.get("role") for m in out]
    for i in range(1, len(roles)):
        if roles[i] == "user":
            assert roles[i - 1] not in ("tool", "user"), f"user at {i} follows {roles[i - 1]}: {roles}"


def test_user_after_tool_gets_assistant_bridge():
    """Repro of the live example/investigate crash: the ReflectiveRunner injects
    a reflection `user` right after tool results. Mistral's template raises
    "roles must alternate ... except for tool calls and results". fix_message_list
    must insert a bridging assistant so the turn is closed."""
    msgs = [
        {"role": "system", "content": "protocol"},
        {"role": "user", "content": "audit www.example.com"},
        _asst("c1"),
        {"role": "tool", "tool_call_id": "c1", "content": "html home"},
        _asst("c2"),
        {"role": "tool", "tool_call_id": "c2", "content": "html contacto"},
        {"role": "user", "content": "reflection: are you making progress?"},  # illegal for Mistral
    ]
    out = fix_message_list(msgs)
    _no_illegal_user(out)
    # The reflection turn itself is preserved (just bridged).
    assert any(m.get("role") == "user" and "reflection" in (m.get("content") or "") for m in out)


def test_consecutive_users_get_bridge():
    msgs = [
        {"role": "user", "content": "u1"},
        {"role": "user", "content": "u2"},
    ]
    _no_illegal_user(fix_message_list(msgs))


def test_already_alternating_history_is_unchanged():
    msgs = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "u1"},
        {"role": "assistant", "content": "a1"},
        {"role": "user", "content": "u2"},
    ]
    out = fix_message_list(msgs)
    assert [m["role"] for m in out] == ["system", "user", "assistant", "user"]


def test_normal_tool_flow_keeps_no_bridge():
    """A normal assistant->tool->assistant flow (model answers after the tool)
    must NOT get a spurious bridge."""
    msgs = [
        {"role": "user", "content": "go"},
        _asst("c1"),
        {"role": "tool", "tool_call_id": "c1", "content": "r1"},
        {"role": "assistant", "content": "done, here is the result"},
    ]
    out = fix_message_list(msgs)
    assert [m["role"] for m in out] == ["user", "assistant", "tool", "assistant"]
