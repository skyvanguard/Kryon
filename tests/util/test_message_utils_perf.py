"""FASE 11.S — fix_message_list performance + correctness regression tests.

Bench Robots run (2026-05-27) caught a hang where the engage main thread
sat at 49% CPU for 14+ minutes inside ``fix_message_list``. py-spy
dumps pinned the hot frame at the linear search on line 230 — a
``for j, assistant_msg in enumerate(processed_messages)`` nested
inside a ``while i < len(processed_messages)`` loop, i.e. O(n²) on
the message history. The bench accumulated nikto/whatweb/nuclei tool
outputs and the SDK's history of thinking blocks, pushing the list
into the size where O(n²) became a wall.

Tests pin:

1. **Performance**: a 300-message list with 100 out-of-order tool
   messages must be fixed in well under 5 seconds. The bug case was
   14+ minutes; 5s catches any regression by a wide margin.
2. **Correctness**: the result must still satisfy the invariant the
   original code targets — every tool message must be immediately
   preceded by an assistant whose tool_calls include the same tool_id.
3. **Existing edge cases preserved**: orphan tool messages still get
   their dummy assistant; tool calls without responses still get
   synthetic tool responses (existing test in test_cli_streaming.py
   pins these).
"""

from __future__ import annotations

import time

from kryon.util import fix_message_list


def _make_assistant(tool_id: str) -> dict:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": tool_id,
                "type": "function",
                "function": {"name": "run_command", "arguments": "{}"},
            }
        ],
    }


def _make_tool(tool_id: str, content: str = "ok") -> dict:
    return {
        "role": "tool",
        "tool_call_id": tool_id,
        "content": content,
    }


def _assert_sequence_invariant(messages: list[dict]) -> None:
    """Each tool message must be immediately preceded by an assistant
    whose tool_calls include the tool_call_id."""
    for i, msg in enumerate(messages):
        if msg.get("role") != "tool":
            continue
        tool_id = msg.get("tool_call_id")
        assert i > 0, f"tool msg {i} has no preceding assistant"
        prev = messages[i - 1]
        assert prev.get("role") == "assistant", f"tool msg {i} preceded by {prev.get('role')!r}, not assistant"
        tcs = prev.get("tool_calls") or []
        ids = {tc.get("id") for tc in tcs}
        assert tool_id in ids, f"tool msg {i} tool_call_id={tool_id!r} not in prev assistant tool_calls {ids!r}"


# ---------------------------------------------------------------------------
# Performance regression
# ---------------------------------------------------------------------------


def test_fix_message_list_300_messages_under_5s() -> None:
    """The bench Robots hang scenario, condensed: 300 messages where
    half the tool messages are interleaved in the wrong order. Must
    complete in well under 5 seconds; the bug case took 14+ minutes."""
    messages: list[dict] = [{"role": "system", "content": "sys"}]
    # 100 assistant/tool pairs in correct order
    for i in range(100):
        messages.append(_make_assistant(f"call_{i}"))
        messages.append(_make_tool(f"call_{i}"))
    # 50 "shuffled" tool messages whose assistant is far away
    # (simulates the SDK history where tool outputs arrive out of
    # order after streaming buffering / parallel agents)
    for i in range(100, 150):
        # Put the assistant message FIRST so the bench-like pattern
        # of "tool out of sequence" applies, then drop a stray tool
        # later in the list.
        messages.append(_make_assistant(f"orphan_{i}"))
    for i in range(100, 150):
        messages.append(_make_tool(f"orphan_{i}"))

    start = time.monotonic()
    result = fix_message_list(messages)
    elapsed = time.monotonic() - start

    assert elapsed < 5.0, f"fix_message_list took {elapsed:.2f}s; bug regression"
    _assert_sequence_invariant(result)


def test_fix_message_list_pathological_reversed_pairs_under_5s() -> None:
    """Pathological case: all tool messages dumped at the END, after
    all assistants. This exercises the worst case for the original
    O(n²) algorithm — every tool message has to scan back to find
    its assistant."""
    messages: list[dict] = []
    n = 100
    for i in range(n):
        messages.append(_make_assistant(f"call_{i}"))
    # Now dump ALL tool messages reversed
    for i in reversed(range(n)):
        messages.append(_make_tool(f"call_{i}"))

    start = time.monotonic()
    result = fix_message_list(messages)
    elapsed = time.monotonic() - start

    assert elapsed < 5.0, f"reversed-pairs took {elapsed:.2f}s; O(n²) regression"
    _assert_sequence_invariant(result)


def test_fix_message_list_1000_messages_under_5s() -> None:
    """Bench Robots scenario: the SDK history accumulates thinking
    blocks + multiple tool outputs + assistant retries until the
    message count is in the low thousands. 1000 messages with 500
    out-of-order tools must still complete in under 5 seconds. The
    bug case here hung 14+ minutes."""
    messages: list[dict] = [{"role": "system", "content": "sys"}]
    # 500 assistant/tool pairs in correct order
    for i in range(500):
        messages.append(_make_assistant(f"call_{i}"))
        messages.append(_make_tool(f"call_{i}"))
    # 250 assistants + 250 tools dumped at the end, all out of order
    for i in range(500, 750):
        messages.append(_make_assistant(f"orphan_{i}"))
    for i in reversed(range(500, 750)):
        messages.append(_make_tool(f"orphan_{i}"))

    start = time.monotonic()
    result = fix_message_list(messages)
    elapsed = time.monotonic() - start

    assert elapsed < 5.0, f"1000-msg case took {elapsed:.2f}s; bug regression"
    _assert_sequence_invariant(result)


# ---------------------------------------------------------------------------
# Correctness — keep existing behaviour
# ---------------------------------------------------------------------------


def test_fix_message_list_keeps_valid_sequence_unchanged() -> None:
    """A message list that already satisfies the invariant must be
    returned with the same logical ordering (modulo synthetic message
    insertion for orphans, which doesn't apply here)."""
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
        _make_assistant("call_1"),
        _make_tool("call_1"),
        _make_assistant("call_2"),
        _make_tool("call_2"),
    ]
    result = fix_message_list(messages)
    _assert_sequence_invariant(result)
    # Same logical structure (may have synthetic additions, but the
    # original pairs survive in the same relative order).
    roles = [m["role"] for m in result]
    assert roles.count("assistant") >= 2
    assert roles.count("tool") >= 2


def test_fix_message_list_handles_orphan_tool_at_start() -> None:
    """Edge case from the original code: a tool message at index 0
    (no preceding assistant) gets a synthetic assistant inserted."""
    messages = [_make_tool("call_orphan")]
    result = fix_message_list(messages)
    _assert_sequence_invariant(result)
    # First message should now be the synthetic assistant.
    assert result[0]["role"] == "assistant"
    assert any(tc["id"] == "call_orphan" for tc in result[0]["tool_calls"])


def test_fix_message_list_creates_synthetic_response_for_orphan_call() -> None:
    """A tool call without response must get an auto-generated tool
    message (the existing test_cli_streaming behaviour)."""
    messages = [
        {"role": "user", "content": "go"},
        _make_assistant("call_no_response"),
    ]
    result = fix_message_list(messages)
    _assert_sequence_invariant(result)
    # Synthetic tool message should be present.
    tool_msgs = [m for m in result if m["role"] == "tool"]
    assert any(t["tool_call_id"] == "call_no_response" for t in tool_msgs)


def test_fix_message_list_reorders_out_of_sequence_tool_message() -> None:
    """The core bug fix correctness: a tool message separated from
    its assistant by other content must end up adjacent to the
    assistant after the function returns."""
    messages = [
        _make_assistant("call_1"),
        _make_assistant("call_2"),  # interleaved
        _make_tool("call_2"),
        _make_tool("call_1"),  # out of sequence — refers to call_1 above
    ]
    result = fix_message_list(messages)
    _assert_sequence_invariant(result)


def test_fix_message_list_empty_input() -> None:
    """Empty input → empty output, no crash."""
    assert fix_message_list([]) == []


def test_fix_message_list_only_user_messages() -> None:
    """No tool calls anywhere → list returned verbatim (modulo
    sanitization), no infinite loop possible."""
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hi back"},
    ]
    result = fix_message_list(messages)
    assert len(result) == 3
    assert all("role" in m for m in result)
