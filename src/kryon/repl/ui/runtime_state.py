"""Runtime state shared between the REPL loop (writer) and the toolbar
background thread (reader).

The toolbar updater runs in a daemon thread that has no reference to
the live `agent` object owned by the REPL loop in `_original.py`. This
module bridges that gap with a simple thread-safe singleton:

  REPL loop, on each turn:
      runtime_state.set_active_agent(agent)

  Toolbar background thread:
      skill_names = runtime_state.get_active_skill_names()
      tool_count  = runtime_state.get_tool_count()

Failures in the agent's attribute extraction degrade silently to
empty defaults — toolbar must NEVER raise.
"""

from __future__ import annotations

import threading
from typing import Any

_lock = threading.Lock()
_state: dict[str, Any] = {
    "skill_names": [],
    "tool_count": 0,
}


def set_active_agent(agent: Any) -> None:
    """Update shared state from the live agent. Called once per REPL turn."""
    skill_names: list[str] = []
    tool_count = 0
    try:
        for s in getattr(agent, "_active_skills", None) or []:
            name = getattr(s, "name", None)
            if name:
                skill_names.append(str(name))
    except Exception:
        skill_names = []
    try:
        tools = getattr(agent, "tools", None) or []
        tool_count = len(tools)
    except Exception:
        tool_count = 0

    with _lock:
        _state["skill_names"] = skill_names
        _state["tool_count"] = tool_count


def get_active_skill_names() -> list[str]:
    """Snapshot of the currently active skill names. Empty if unset."""
    with _lock:
        return list(_state.get("skill_names") or [])


def get_tool_count() -> int:
    """Number of tools bound to the active agent."""
    with _lock:
        return int(_state.get("tool_count") or 0)


def reset() -> None:
    """Test helper — wipe the state."""
    with _lock:
        _state["skill_names"] = []
        _state["tool_count"] = 0
