"""
Test that no agent exceeds 15 tools.

This prevents tool overload which degrades LLM effectiveness.
"""

import pytest

from kryon.agents import get_available_agents


MAX_TOOLS_PER_AGENT = 25  # Hard limit — forensic_analyzer has DFIR specialization tools


def test_no_agent_exceeds_tool_limit():
    """No agent should have more than MAX_TOOLS_PER_AGENT tools."""
    agents = get_available_agents(include_patterns=False)
    violations = []

    for name, agent in agents.items():
        tool_count = len(agent.tools) if agent.tools else 0
        if tool_count > MAX_TOOLS_PER_AGENT:
            violations.append(f"{name}: {tool_count} tools (max {MAX_TOOLS_PER_AGENT})")

    assert not violations, (
        f"Agents exceeding {MAX_TOOLS_PER_AGENT} tool limit:\n"
        + "\n".join(f"  - {v}" for v in violations)
    )


def test_ctf_master_reduced():
    """CTF Master should have 15 or fewer tools (was 37)."""
    agents = get_available_agents(include_patterns=False)
    ctf = agents.get("CTF Master")
    assert ctf is not None, "CTF Master agent not found"
    assert len(ctf.tools) <= 15, f"CTF Master has {len(ctf.tools)} tools, expected <= 15"


def test_vuln_hunter_reduced():
    """Vuln Hunter should have 15 or fewer tools (was 17)."""
    agents = get_available_agents(include_patterns=False)
    vh = agents.get("Vuln Hunter")
    assert vh is not None, "Vuln Hunter agent not found"
    assert len(vh.tools) <= 15, f"Vuln Hunter has {len(vh.tools)} tools, expected <= 15"


def test_all_agents_have_tools():
    """Every agent should have at least 1 tool."""
    agents = get_available_agents(include_patterns=False)
    no_tools = []

    for name, agent in agents.items():
        if not agent.tools or len(agent.tools) == 0:
            no_tools.append(name)

    assert not no_tools, (
        f"Agents with no tools:\n" + "\n".join(f"  - {n}" for n in no_tools)
    )
