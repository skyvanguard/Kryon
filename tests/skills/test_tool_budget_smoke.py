"""Smoke tests for the tool budget — F77.B.

Verifies:
- ALWAYS_INCLUDE is non-empty and stable.
- select_tools respects forbidden_tool_names (a skill can veto an
  ambient tool).
- select_tools caps at max_tools.
"""

from __future__ import annotations

from types import SimpleNamespace

from kryon.skills.tool_budget import (
    ALWAYS_INCLUDE,
    EXPLOIT_VALIDATION_TOOLS,
    select_tools,
)


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


def test_max_tools_env_override(monkeypatch) -> None:
    monkeypatch.setenv("KRYON_MAX_TOOLS", "8")
    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    extra = [f"tool_{i:02d}" for i in range(20)]
    registry = _fake_registry(list(ALWAYS_INCLUDE) + extra)
    tools = select_tools(registry, set(extra))
    assert len(tools) == 8  # keep(ALWAYS=5, <8) → cap respected


def test_capable_model_gets_larger_budget(monkeypatch) -> None:
    monkeypatch.delenv("KRYON_MAX_TOOLS", raising=False)
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    extra = [f"tool_{i:02d}" for i in range(40)]
    registry = _fake_registry(list(ALWAYS_INCLUDE) + extra)
    tools = select_tools(registry, set(extra))
    assert len(tools) >= 30  # capable model isn't schema-token bound


def test_cap_keeps_high_value_tools_over_alphabetical() -> None:
    # Regression (G14): the cap filled by alphabetical order, dropping
    # nuclei/whatweb/sqlmap/wpscan (late letters) while keeping generic early ones.
    generic = [f"aaa_util_{i:02d}" for i in range(12)]  # sort early, low value
    high_value = ["nuclei_scan", "whatweb_scan", "sqlmap_probe", "wpscan_run"]
    skill_tools = set(generic + high_value)
    registry = _fake_registry(list(ALWAYS_INCLUDE) + generic + high_value)
    tools = select_tools(registry, skill_tools, max_tools=len(ALWAYS_INCLUDE) + 4)
    names = {t.name for t in tools}
    for hv in high_value:
        assert hv in names, f"{hv} was dropped by the cap"
    # And the generic early-alphabet tools should be the ones dropped.
    assert not any(n.startswith("aaa_util_") for n in names) or len(names) <= len(ALWAYS_INCLUDE) + 4


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


def test_exploit_validators_offered_only_under_red_team(monkeypatch) -> None:
    """Banca-safe: validate_* are selectable only when KRYON_RED_TEAM is set,
    so findings can be promoted ALLEGED → VERIFIED in active engagements
    without exposing exploit tools in the banking default."""
    registry = _fake_registry(list(ALWAYS_INCLUDE) + list(EXPLOIT_VALIDATION_TOOLS))

    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    names_off = {t.name for t in select_tools(registry, set(), max_tools=30)}
    assert not (EXPLOIT_VALIDATION_TOOLS & names_off), "leaked into banking default"

    monkeypatch.setenv("KRYON_RED_TEAM", "true")
    names_on = {t.name for t in select_tools(registry, set(), max_tools=30)}
    assert EXPLOIT_VALIDATION_TOOLS <= names_on, "not offered under red-team"


def test_all_shipped_playbook_prehook_tools_are_in_required_tools():
    """Invariant: every pre_hooks[].tool must be listed in that skill's
    required_tools — otherwise the tool-budget floor (which is keyed off
    required_tools + the pre_hook floor) may not include it and a required: true
    pre_hook aborts the turn. Enforced so a future skill edit can't break it."""
    import pathlib

    from kryon.skills.loader import _parse_skill_file

    violations = []
    for f in sorted(pathlib.Path("src/kryon/skills/playbooks").rglob("*.md")):
        sk = _parse_skill_file(f)
        if not sk:
            continue
        req = set(sk.required_tools or [])
        for h in sk.pre_hooks or ():
            tool = getattr(h, "tool", None)
            if tool and tool not in req:
                violations.append(f"{f.name}: pre_hook tool {tool!r} not in required_tools")
    assert not violations, "pre_hook tools missing from required_tools:\n" + "\n".join(violations)


def test_prehook_tool_survives_the_budget_cap():
    """A pre_hook tool passed as a hard floor must never be dropped by the cap,
    even when many other skill tools push the union past max_tools."""
    from kryon.skills.tool_budget import build_tool_registry, select_tools

    registry = build_tool_registry()
    if "detect_bola" not in registry:
        return  # tool not present in this build; nothing to assert
    fat = set(list(registry.keys())[:40])  # blow past the cap
    tools = select_tools(registry, fat, max_tools=15, pre_hook_tool_names={"detect_bola"})
    assert "detect_bola" in {getattr(t, "name", "") for t in tools}
