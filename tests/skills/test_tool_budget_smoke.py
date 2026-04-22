"""Smoke tests for the tool budget — F77.B.

Verifies:
- ALWAYS_INCLUDE is non-empty and stable.
- select_tools respects forbidden_tool_names (a skill can veto an
  ambient tool).
- select_tools caps at max_tools.
"""

from __future__ import annotations

from types import SimpleNamespace

from kryon.skills.tool_budget import ALWAYS_INCLUDE, select_tools


def _fake_registry(names: list[str]) -> dict[str, object]:
    return {n: SimpleNamespace(name=n) for n in names}


def test_always_include_non_empty() -> None:
    assert len(ALWAYS_INCLUDE) > 0
    assert "run_command" in ALWAYS_INCLUDE


def test_select_tools_includes_always() -> None:
    registry = _fake_registry(list(ALWAYS_INCLUDE) + ["custom_skill_tool"])
    tools = select_tools(registry, {"custom_skill_tool"})
    names = {t.name for t in tools}
    assert "run_command" in names
    assert "custom_skill_tool" in names


def test_select_tools_respects_forbidden() -> None:
    """A skill's forbidden_tools must win over ALWAYS_INCLUDE.

    The zero-day-hunter relies on this to veto run_command so the model
    can't side-channel around run_sandboxed.
    """
    registry = _fake_registry(list(ALWAYS_INCLUDE))
    tools = select_tools(
        registry,
        set(),
        forbidden_tool_names={"run_command"},
    )
    names = {t.name for t in tools}
    assert "run_command" not in names
    # Other ALWAYS_INCLUDE tools stay available.
    assert "nmap" in names


def test_select_tools_never_exceeds_cap() -> None:
    many = [f"tool_{i}" for i in range(100)]
    registry = _fake_registry(list(ALWAYS_INCLUDE) + many)
    tools = select_tools(registry, set(many), max_tools=15)
    assert len(tools) <= 15
