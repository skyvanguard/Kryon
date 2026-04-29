"""TDD contract for kryon.repl.ui.runtime_state.

Module-level shared state so the toolbar (running in a background
thread) can read what the agent loop sees, without passing the agent
object around the codebase.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_state():
    """Each test starts with a clean slate."""
    from kryon.repl.ui.runtime_state import reset

    reset()
    yield
    reset()


class _Skill:
    def __init__(self, name: str) -> None:
        self.name = name


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name


class _Agent:
    def __init__(self, skills: list, tools: list) -> None:
        self._active_skills = skills
        self.tools = tools


# ---------- Initial / cleared state ----------


def test_get_active_skills_empty_when_unset() -> None:
    from kryon.repl.ui.runtime_state import get_active_skill_names

    assert get_active_skill_names() == []


def test_get_tool_count_zero_when_unset() -> None:
    from kryon.repl.ui.runtime_state import get_tool_count

    assert get_tool_count() == 0


# ---------- Set / read ----------


def test_set_active_agent_populates_skills_and_tools() -> None:
    from kryon.repl.ui.runtime_state import (
        get_active_skill_names,
        get_tool_count,
        set_active_agent,
    )

    agent = _Agent(
        skills=[_Skill("fortigate-audit"), _Skill("recon-scout")],
        tools=[_Tool(f"t{i}") for i in range(14)],
    )
    set_active_agent(agent)

    assert get_active_skill_names() == ["fortigate-audit", "recon-scout"]
    assert get_tool_count() == 14


def test_set_active_agent_updates_on_subsequent_calls() -> None:
    """Hot-swap: state reflects the latest agent set."""
    from kryon.repl.ui.runtime_state import (
        get_active_skill_names,
        set_active_agent,
    )

    set_active_agent(_Agent(skills=[_Skill("a")], tools=[]))
    assert get_active_skill_names() == ["a"]

    set_active_agent(_Agent(skills=[_Skill("b"), _Skill("c")], tools=[]))
    assert get_active_skill_names() == ["b", "c"]


def test_handles_agent_without_active_skills_attr() -> None:
    """Bare agent objects degrade gracefully — empty list, no crash."""
    from kryon.repl.ui.runtime_state import (
        get_active_skill_names,
        set_active_agent,
    )

    class _Bare:
        pass

    set_active_agent(_Bare())
    assert get_active_skill_names() == []


def test_handles_agent_without_tools_attr() -> None:
    from kryon.repl.ui.runtime_state import get_tool_count, set_active_agent

    class _Bare:
        pass

    set_active_agent(_Bare())
    assert get_tool_count() == 0


# ---------- Thread safety ----------


def test_concurrent_set_and_read_does_not_crash() -> None:
    """Toolbar reads in a background thread; REPL writes from main thread.
    Smoke test that concurrent access doesn't raise."""
    import threading

    from kryon.repl.ui.runtime_state import (
        get_active_skill_names,
        set_active_agent,
    )

    stop = threading.Event()

    def writer():
        i = 0
        while not stop.is_set():
            set_active_agent(_Agent(skills=[_Skill(f"s{i}")], tools=[]))
            i += 1

    def reader():
        while not stop.is_set():
            get_active_skill_names()

    t1 = threading.Thread(target=writer, daemon=True)
    t2 = threading.Thread(target=reader, daemon=True)
    t1.start()
    t2.start()
    import time
    time.sleep(0.05)
    stop.set()
    t1.join(timeout=1)
    t2.join(timeout=1)


# ---------- Reset ----------


def test_reset_clears_state() -> None:
    from kryon.repl.ui.runtime_state import (
        get_active_skill_names,
        get_tool_count,
        reset,
        set_active_agent,
    )

    set_active_agent(_Agent(skills=[_Skill("x")], tools=[_Tool("t")]))
    assert get_active_skill_names() == ["x"]

    reset()
    assert get_active_skill_names() == []
    assert get_tool_count() == 0
