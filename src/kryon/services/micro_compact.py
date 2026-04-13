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
