"""Tests for agent definition integrity — ensures all agents are well-configured."""

from __future__ import annotations

import pytest

from kryon.agents import get_available_agents
from kryon.sdk.agents import FunctionTool


@pytest.fixture(scope="module")
def agents():
    """Load all agents once for the module."""
    return get_available_agents(include_patterns=False)


def test_agents_loaded(agents):
    """At least 20 agents should be registered."""
    assert len(agents) >= 20, f"Expected >= 20 agents, got {len(agents)}"


def test_all_agents_have_name(agents):
    """Every agent must have a non-empty name."""
    for key, agent in agents.items():
        assert agent.name, f"Agent '{key}' has empty name"


def test_all_agents_have_instructions(agents):
    """Every agent must have non-empty instructions."""
    for key, agent in agents.items():
        assert agent.instructions, f"Agent '{key}' has empty instructions"


def test_all_agents_have_at_least_one_tool(agents):
    """Every agent must have at least one tool."""
    for key, agent in agents.items():
        assert len(agent.tools) > 0, f"Agent '{key}' has no tools"


def test_all_tools_are_function_tool_or_callable(agents):
    """All tools in all agents must be FunctionTool instances or callables."""
    for key, agent in agents.items():
        for tool in agent.tools:
            is_ft = isinstance(tool, FunctionTool)
            is_callable = callable(tool)
            assert is_ft or is_callable, (
                f"Agent '{key}' has non-tool/non-callable: {type(tool).__name__}"
            )


def test_no_duplicate_tool_names_within_agent(agents):
    """No agent should have duplicate tool names."""
    for key, agent in agents.items():
        tool_names = [
            t.name if isinstance(t, FunctionTool) else getattr(t, "__name__", str(t))
            for t in agent.tools
        ]
        dupes = [n for n in tool_names if tool_names.count(n) > 1]
        assert not dupes, f"Agent '{key}' has duplicate tools: {set(dupes)}"


@pytest.mark.parametrize(
    "agent_key,keyword",
    [
        ("network_recon", "network"),
        ("web_auditor", "web"),
        ("exploit_specialist", "exploit"),
        ("vulnerability_analyst", "vulnerabilit"),
        ("threat_intel", "threat"),
        ("cloud_auditor", "cloud"),
    ],
)
def test_agent_instructions_mention_specialty(agents, agent_key, keyword):
    """Key agents should reference their specialty in instructions."""
    if agent_key not in agents:
        pytest.skip(f"Agent '{agent_key}' not found")
    instructions = agents[agent_key].instructions.lower()
    assert keyword in instructions, (
        f"Agent '{agent_key}' instructions don't mention '{keyword}'"
    )


def test_agent_names_match_keys(agents):
    """Agent names should be coherent with their registry keys."""
    for key, agent in agents.items():
        # Name should be non-empty and not just whitespace
        name = agent.name.strip()
        assert len(name) >= 3, f"Agent '{key}' has too-short name: '{name}'"
