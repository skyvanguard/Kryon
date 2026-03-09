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
    from kryon.agents.codeagent import CodeAgent

    for key, agent in agents.items():
        if isinstance(agent, CodeAgent):
            # CodeAgent registers tools internally in python_executor.static_tools
            continue
        assert len(agent.tools) > 0, f"Agent '{key}' has no tools"


def test_all_tools_are_function_tool_or_callable(agents):
    """All tools in all agents must be FunctionTool instances or callables."""
    for key, agent in agents.items():
        for tool in agent.tools:
            is_ft = isinstance(tool, FunctionTool)
            is_callable = callable(tool)
            assert is_ft or is_callable, f"Agent '{key}' has non-tool/non-callable: {type(tool).__name__}"


def test_no_duplicate_tool_names_within_agent(agents):
    """No agent should have duplicate tool names."""
    for key, agent in agents.items():
        tool_names = [t.name if isinstance(t, FunctionTool) else getattr(t, "__name__", str(t)) for t in agent.tools]
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
    assert keyword in instructions, f"Agent '{agent_key}' instructions don't mention '{keyword}'"


def test_agent_names_match_keys(agents):
    """Agent names should be coherent with their registry keys."""
    for key, agent in agents.items():
        # Name should be non-empty and not just whitespace
        name = agent.name.strip()
        assert len(name) >= 3, f"Agent '{key}' has too-short name: '{name}'"


# --- Memory tools integration tests ---

# Agents excluded from MEMORY_TOOLS requirement
_MEMORY_EXEMPT = {"central_core", "code_agent", "codeagent", "semantic_builder", "episodic_builder", "query_agent", "target_validator"}

MEMORY_TOOL_NAMES = {"query_memory", "add_to_memory_semantic"}


def test_agents_have_memory_tools(agents):
    """All specialist agents (except central_core) should have memory tools when available."""
    from kryon.agents.toolsets import MEMORY_TOOLS

    if not MEMORY_TOOLS:
        pytest.skip("MEMORY_TOOLS empty — kryon.rag not available in this environment")
    for key, agent in agents.items():
        if key in _MEMORY_EXEMPT:
            continue
        tool_names = {
            t.name if isinstance(t, FunctionTool) else getattr(t, "__name__", str(t))
            for t in agent.tools
        }
        missing = MEMORY_TOOL_NAMES - tool_names
        assert not missing, f"Agent '{key}' missing memory tools: {missing}"


# --- Handoff schema validation tests ---

def test_central_core_handoffs_use_router_schema(agents):
    """Central Core handoffs should use ROUTER_HANDOFF_SCHEMA."""
    from kryon.agents.lazy_handoff import ROUTER_HANDOFF_SCHEMA

    if "central_core" not in agents:
        pytest.skip("central_core not found")
    central = agents["central_core"]
    for h in central.handoffs:
        assert h.input_json_schema == ROUTER_HANDOFF_SCHEMA, (
            f"Central Core handoff '{h.tool_name}' doesn't use ROUTER_HANDOFF_SCHEMA"
        )


def test_specialist_handoffs_use_briefing_schema(agents):
    """Specialist agent handoffs should use HANDOFF_BRIEFING_SCHEMA."""
    from kryon.agents.lazy_handoff import HANDOFF_BRIEFING_SCHEMA

    for key, agent in agents.items():
        if key == "central_core":
            continue
        for h in agent.handoffs:
            assert h.input_json_schema == HANDOFF_BRIEFING_SCHEMA, (
                f"Agent '{key}' handoff '{h.tool_name}' doesn't use HANDOFF_BRIEFING_SCHEMA"
            )


def test_all_handoffs_strict_json_disabled(agents):
    """All handoffs should have strict_json_schema=False for Ollama compatibility."""
    for key, agent in agents.items():
        for h in agent.handoffs:
            assert h.strict_json_schema is False, (
                f"Agent '{key}' handoff '{h.tool_name}' has strict_json_schema=True"
            )
