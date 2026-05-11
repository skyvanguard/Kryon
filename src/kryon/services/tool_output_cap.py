"""
Tool output size cap — prevent large tool results from consuming the
entire 32K context window.

Ported from Claude Code's `constants/toolLimits.ts` pattern.

When a tool result exceeds MAX_TOOL_RESULT_CHARS, the full output is
persisted to disk and the model receives a preview (head + tail) with
a pointer to the file. This saves ~80% of context for tool results.

Usage:
    from kryon.services.tool_output_cap import cap_tool_output
    capped = cap_tool_output(raw_output, tool_name="nmap")
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_TOOL_RESULT_CHARS = int(os.environ.get("KRYON_MAX_TOOL_RESULT", "5000"))
TOOL_OUTPUT_DIR = os.environ.get("KRYON_TOOL_OUTPUT_DIR", "/workspace/tool_outputs")

_HEAD_CHARS = 500
_TAIL_CHARS = 200


def cap_tool_output(content: str, tool_name: str = "tool") -> str:
    """If content exceeds the cap, save to disk and return a preview.

    Args:
        content: Raw tool output string.
        tool_name: Name of the tool (used in the filename).

    Returns:
        Original content if under cap, or truncated preview with file path.
    """
    if not isinstance(content, str) or len(content) <= MAX_TOOL_RESULT_CHARS:
        return content

    # Clean tool name for filesystem
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in tool_name)[:30]
    timestamp = datetime.now(timezone.utc).strftime("%H%M%S")
    filename = f"{safe_name}_{timestamp}.txt"
    filepath = Path(TOOL_OUTPUT_DIR) / filename

    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content, encoding="utf-8")
        saved_msg = f"full output saved to {filepath}"
    except Exception as e:
        logger.warning("Failed to save tool output to %s: %s", filepath, e)
        saved_msg = "full output could not be saved"

    total = len(content)
    head = content[:_HEAD_CHARS]
    tail = content[-_TAIL_CHARS:] if _TAIL_CHARS else ""

    return f"{head}\n\n[... {total} chars total — {saved_msg} ...]\n\n{tail}"
