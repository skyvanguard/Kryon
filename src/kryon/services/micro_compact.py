"""
MicroCompact — trim old tool outputs in message history.

Ported from Claude Code's `services/compact/microCompact.ts`.

After the model processes a tool result (generates an assistant response),
the full tool output is no longer needed verbatim in the context window.
This module replaces large outputs with a truncated version: first 500 chars
+ last 200 chars + indicator, freeing ~60-80% of each output's tokens.

Only tools whose output is typically large and semi-structured (nmap,
gobuster, nuclei, etc.) are compacted. Short outputs (<budget) are left
untouched.

Usage:
    from kryon.services.micro_compact import micro_compact_history
    trimmed = micro_compact_history(agent.model.message_history)
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Tools whose outputs are large enough to benefit from trimming.
# Names should match how they appear in tool_call_id or the preceding
# assistant tool_calls[].function.name.
LARGE_OUTPUT_TOOLS: set[str] = {
    "nmap",
    "run_command",
    "nuclei_scan",
    "whatweb_scan",
    "gobuster",
    "nikto",
    "curl_request",
    "dirb",
    "execute_code",
    "duckduckgo_search",
}

_HEAD = 500  # chars to keep from the start
_TAIL = 200  # chars to keep from the end


def _should_compact(content: str, budget: int) -> bool:
    """Return True if the content exceeds the budget and is worth trimming."""
    return isinstance(content, str) and len(content) > budget


def _truncate(content: str) -> str:
    """Replace the middle of a long string with a truncation marker."""
    n = len(content)
    head = content[:_HEAD]
    tail = content[-_TAIL:] if _TAIL else ""
    removed = n - _HEAD - _TAIL
    return f"{head}\n\n[...{removed} chars truncated by micro-compact...]\n\n{tail}"


def _tool_name_from_history(history: list[dict], tool_idx: int) -> str | None:
    """Walk backward from a tool-result message to find its tool name in the
    preceding assistant tool_calls."""
    call_id = history[tool_idx].get("tool_call_id")
    if not call_id:
        return None
    # Search backward for the assistant message that issued this call
    for i in range(tool_idx - 1, -1, -1):
        msg = history[i]
        if msg.get("role") != "assistant":
            continue
        for tc in msg.get("tool_calls") or []:
            tc_id = tc.get("id") or (tc.get("function") or {}).get("id")
            if tc_id == call_id:
                return (tc.get("function") or {}).get("name")
        # Only search one assistant message back
        break
    return None


def micro_compact_history(
    history: list[dict],
    budget: int = 1000,
    tools: set[str] | None = None,
) -> int:
    """Trim large tool outputs in-place that the model has already processed.

    A tool output is "already processed" if there is at least one
    ``role=assistant`` message **after** it in the history (meaning the
    model generated a response that incorporated the output).

    Args:
        history: The mutable message_history list from the model adapter.
        budget: Minimum content length (chars) before trimming applies.
        tools: Set of tool names to compact. Defaults to LARGE_OUTPUT_TOOLS.

    Returns:
        Number of messages truncated.
    """
    if not history:
        return 0

    target_tools = tools or LARGE_OUTPUT_TOOLS
    trimmed = 0

    # Find the index of the last assistant message — anything before it
    # has already been read by the model.
    last_assistant_idx = -1
    for i in range(len(history) - 1, -1, -1):
        if history[i].get("role") == "assistant":
            last_assistant_idx = i
            break

    if last_assistant_idx < 1:
        return 0  # nothing to compact

    for i in range(last_assistant_idx):
        msg = history[i]
        if msg.get("role") != "tool":
            continue
        content = msg.get("content")
        if not _should_compact(content, budget):
            continue

        # Check if this tool is in the allow-list
        tool_name = _tool_name_from_history(history, i)
        if tool_name and tool_name not in target_tools:
            # Also try without namespace prefix (gemma "nmap:nmap" → "nmap")
            if ":" in tool_name:
                tool_name = tool_name.rsplit(":", 1)[-1]
            if tool_name not in target_tools:
                continue

        # Truncate in-place
        original_len = len(content)
        msg["content"] = _truncate(content)
        trimmed += 1
        logger.debug(
            "micro-compact: trimmed tool output %s (%d → %d chars)",
            tool_name or "?",
            original_len,
            len(msg["content"]),
        )

    return trimmed


# ---------------------------------------------------------------------------
# Hunter-session compaction (F3.5)
# ---------------------------------------------------------------------------
#
# When a hunter sub-agent finishes and hands its results back to the
# supervisor, the supervisor doesn't need the hunter's full turn-by-turn
# history — just the initial prompt, any confirmed findings, and the last
# few turns (for context). This aggressive compaction is what extends the
# horizon from ~2h to ~16h (ARTEMIS claim).


# Markers that identify a "kept" message even if it's deep in history.
_FINDING_MARKERS = (
    "FINDING",
    "VARIANT FINDING",
    "FUZZ HARNESS",
    "crashed=True",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "undefined-behavior",
)
# Markers we shrink to one line (noise during compaction).
_DISCARDED_MARKERS = (
    "discarded-hypothesis",
    "no crash",
    "hypothesis discarded",
)


def _is_finding_message(msg: dict) -> bool:
    if msg.get("role") != "assistant":
        return False
    content = msg.get("content")
    if not isinstance(content, str):
        return False
    return any(m in content for m in _FINDING_MARKERS)


def _is_discarded_summary(msg: dict) -> bool:
    content = msg.get("content")
    if not isinstance(content, str):
        return False
    return any(m in content for m in _DISCARDED_MARKERS)


def compact_hunter_session(
    messages: list[dict],
    *,
    keep_last_n: int = 5,
    keep_system: bool = True,
) -> list[dict]:
    """Compact a single hunter's session into a supervisor-consumable summary.

    Keeps:
      - system prompt (first message if role=system)
      - the initial user prompt (the dynamic-prompt body)
      - every assistant message that looks like a confirmed finding
      - the last `keep_last_n` turns (assistant + tool pairs)
    Compresses:
      - discarded-hypothesis messages → one line each
      - intermediate tool outputs → "[tool <name>: N chars, not retained]"

    Returns a NEW list (does not mutate the input).
    """
    if not messages:
        return []

    kept: list[dict] = []

    # 1. System prompt
    if keep_system and messages[0].get("role") == "system":
        kept.append(messages[0])
        start = 1
    else:
        start = 0

    # 2. Initial user prompt — the first user message is the mission brief
    initial_user_idx: int | None = None
    for i in range(start, len(messages)):
        if messages[i].get("role") == "user":
            kept.append(messages[i])
            initial_user_idx = i
            break

    if initial_user_idx is None:
        return kept  # nothing else to process

    # 3. Mark boundary for "last N turns" preservation
    last_n_start = max(initial_user_idx + 1, len(messages) - keep_last_n)

    discarded_count = 0
    dropped_tool_outputs = 0
    dropped_chars = 0

    for i in range(initial_user_idx + 1, len(messages)):
        msg = messages[i]
        role = msg.get("role")

        # Always keep recent messages
        if i >= last_n_start:
            kept.append(msg)
            continue

        # Keep any assistant message that looks like a finding
        if _is_finding_message(msg):
            kept.append(msg)
            continue

        # Compress discarded-hypothesis mentions to a single terse line
        if _is_discarded_summary(msg):
            discarded_count += 1
            continue

        # Drop intermediate tool outputs, replace with a stub
        if role == "tool":
            content = msg.get("content")
            if isinstance(content, str) and len(content) > 200:
                tool_name = _tool_name_from_history(messages, i) or "?"
                stub = {
                    "role": "tool",
                    "tool_call_id": msg.get("tool_call_id", ""),
                    "content": f"[tool {tool_name}: {len(content)} chars, compacted]",
                }
                kept.append(stub)
                dropped_tool_outputs += 1
                dropped_chars += len(content) - len(stub["content"])
                continue
            # Short tool output — keep verbatim
            kept.append(msg)
            continue

        # Default: keep assistant messages that aren't findings either (they
        # contain hypothesis/reasoning the supervisor may skim). Compress if
        # very long.
        if role == "assistant":
            content = msg.get("content") or ""
            if isinstance(content, str) and len(content) > 1500:
                msg = dict(msg)
                msg["content"] = content[:1200] + "\n[... truncated ...]"
                dropped_chars += len(content) - len(msg["content"])
            kept.append(msg)

    # Inject the discarded-hypothesis roll-up so the supervisor knows
    # that hunter explored and rejected N paths (useful for learning loop).
    if discarded_count:
        kept.append({
            "role": "assistant",
            "content": f"[compacted: {discarded_count} discarded hypotheses during hunt]",
        })

    logger.info(
        "hunter-compact: %d -> %d messages, %d tool outputs stubbed, "
        "%d chars dropped, %d discarded hypotheses rolled up",
        len(messages), len(kept), dropped_tool_outputs,
        dropped_chars, discarded_count,
    )
    return kept
