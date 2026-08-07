"""Wiring test (agentic gap #4): retest_finding is registered + offered.

It was already a @function_tool but never in the tool registry, so the agent
couldn't call it. These assert the one-line wiring holds.
"""

from __future__ import annotations

from pathlib import Path

import yaml


def test_retest_finding_in_registry():
    from kryon.skills.tool_budget import build_tool_registry

    assert "retest_finding" in build_tool_registry()


def test_retest_finding_offered_by_web_pentest_skill():
    md = Path(__file__).resolve().parents[2] / "src/kryon/skills/playbooks/web-pentest.md"
    fm = yaml.safe_load(md.read_text(encoding="utf-8").split("---")[1])
    assert "retest_finding" in fm["required_tools"]
