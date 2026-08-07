"""Regression tests for the MEDIUM/LOW review fixes:
- a BOM-prefixed playbook still parses (Windows editors)
- pre_hook template substitution recurses into list/dict args
- update_agent_skills keeps the sast_review tool on hot-swap (subagents on)
"""

from __future__ import annotations

from pathlib import Path

from kryon.skills.loader import _parse_skill_file
from kryon.skills.pre_hook_runner import _substitute_args


def test_bom_prefixed_frontmatter_parses(tmp_path: Path) -> None:
    md = tmp_path / "bom.md"
    # UTF-8 BOM before the frontmatter fence.
    md.write_bytes(b"\xef\xbb\xbf---\nname: bom-skill\npriority: 7\n---\nbody\n")
    skill = _parse_skill_file(md)
    assert skill is not None
    assert skill.name == "bom-skill"
    assert skill.priority == 7


def test_substitute_recurses_into_list_and_dict() -> None:
    ctx = {"host": "example.com"}
    args = {
        "hosts": ["{ctx.host}", "static"],
        "nested": {"h": "{ctx.host}"},
        "scalar": 42,
    }
    out = _substitute_args(args, ctx)
    assert out["hosts"] == ["example.com", "static"]
    assert out["nested"] == {"h": "example.com"}
    assert out["scalar"] == 42


def test_hot_swap_keeps_sast_tool_when_subagents_enabled(monkeypatch) -> None:
    monkeypatch.setenv("KRYON_SUBAGENTS", "true")
    from kryon.skills import unified_agent

    registry = unified_agent._get_tool_registry()
    if "run_command" not in registry:
        import pytest

        pytest.skip("run_command tool not in registry in this environment")

    tools = unified_agent._wire_ambient_and_subagent_tools([], registry, set())
    names = {getattr(t, "name", "") for t in tools}
    assert "sast_review" in names, "hot-swap wiring must attach sast_review under subagents"
    # ambient tools always present too
    assert "web_fetch_smart" in names
