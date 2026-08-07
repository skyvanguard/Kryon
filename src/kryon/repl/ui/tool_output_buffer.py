"""Per-turn buffer of tool outputs for `/show <N>` recall.

When `render_tool_completion` collapses a long output (> 8 lines), the
full body is stored here keyed by step_id. The user retrieves it with
`/show <N>` (handled by `repl/commands/show.py`).

Design notes:
  * Bounded: caps both per-step bytes and steps-per-turn to avoid
    unbounded memory growth on chatty agents.
  * Per-turn lifetime: `new_turn()` is called by the REPL loop at the
    start of each turn, evicting prior entries. Step ids restart at 1.
  * Audit-safe: this is ONLY the interactive cache. Full outputs still
    land in the JSONL session log regardless of cap.
  * Thread-safe: REPL writes from main thread; toolbar background
    thread or commands may read.
"""

from __future__ import annotations

import threading
from typing import Any

# Max bytes kept per step's output. Beyond this we truncate with a
# marker; the original output still goes to the JSONL log.
MAX_OUTPUT_BYTES_PER_STEP = 65536  # 64 KB

# Per-turn step cap. After this, oldest entries are evicted FIFO so the
# buffer doesn't grow unbounded if the agent loops.
MAX_STEPS_PER_TURN = 256


_lock = threading.Lock()
_state: dict[str, Any] = {
    "next_step": 1,
    "entries": {},  # step_id → {tool_name, output}
}

_TRUNCATION_MARKER = "\n\n[…truncated for /show buffer; full output in session log]"


def _truncate(s: str) -> str:
    if len(s) <= MAX_OUTPUT_BYTES_PER_STEP:
        return s
    head = s[:MAX_OUTPUT_BYTES_PER_STEP]
    return head + _TRUNCATION_MARKER


def _evict_oldest(entries: dict[int, Any], target: int) -> None:
    """Drop oldest entries until len(entries) <= target. Cheap because
    step_ids are monotonic — we just sort by id and pop from the front."""
    if len(entries) <= target:
        return
    sorted_ids = sorted(entries.keys())
    overflow = len(entries) - target
    for sid in sorted_ids[:overflow]:
        entries.pop(sid, None)


def record(*, tool_name: str, output: str | None) -> int:
    """Store one tool's output, return its step_id.

    Step ids restart at 1 each turn. Output is truncated to
    MAX_OUTPUT_BYTES_PER_STEP and the buffer evicts oldest beyond
    MAX_STEPS_PER_TURN.
    """
    body = _truncate(output if isinstance(output, str) else "")
    with _lock:
        sid = _state["next_step"]
        _state["next_step"] = sid + 1
        _state["entries"][sid] = {"tool_name": tool_name or "(unknown)", "output": body}
        _evict_oldest(_state["entries"], MAX_STEPS_PER_TURN)
    return sid


def get(step_id: int) -> dict[str, Any] | None:
    """Look up a step's recorded output. Returns None if absent
    (unknown id, evicted, or buffer was reset by a new turn)."""
    with _lock:
        entry = _state["entries"].get(step_id)
        if entry is None:
            return None
        return dict(entry)  # defensive copy


def new_turn() -> None:
    """Called by the REPL at the start of each user turn. Resets step
    counter and evicts all prior entries."""
    with _lock:
        _state["next_step"] = 1
        _state["entries"] = {}


def live_count() -> int:
    """Number of entries currently in the buffer. For tests + telemetry."""
    with _lock:
        return len(_state["entries"])


def reset() -> None:
    """Test helper — wipe everything (counter + entries)."""
    new_turn()
