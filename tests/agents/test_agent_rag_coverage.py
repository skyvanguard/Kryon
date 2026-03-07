"""
Test that all agents have RAG knowledge base access.

Universal RAG coverage ensures every agent can leverage KRYON's
knowledge base for vulnerability research and exploit techniques.
"""

import pytest

from kryon.agents import get_available_agents


def _get_tool_names(agent):
    """Extract tool function names from an agent's tool list."""
    names = []
    for tool in agent.tools or []:
        # Function tools have a .name attribute, agent-as-tool has tool_name
        name = getattr(tool, "name", None) or getattr(tool, "__name__", str(tool))
        names.append(name)
    return names


def test_all_agents_have_query_knowledge_base():
    """Every agent should have query_knowledge_base tool (except pure routers)."""
    agents = get_available_agents(include_patterns=False)
    # Central Core is a pure router, memory agents are specialized sub-agents
    pure_routers = {"central_core", "semantic_builder", "episodic_builder", "query_agent"}
    missing = []

    for name, agent in agents.items():
        if name in pure_routers:
            continue
        tool_names = _get_tool_names(agent)
        if "query_knowledge_base" not in tool_names:
            missing.append(name)

    assert not missing, "Agents missing query_knowledge_base:\n" + "\n".join(f"  - {n}" for n in missing)


def test_main_agents_have_claude_code():
    """Main operational agents should have claude_code tool."""
    agents = get_available_agents(include_patterns=False)

    # These agents should definitely have claude_code
    expected_agents = [
        "CTF Master",
        "Vuln Hunter",
        "Pentest Agent",
        "Forensic Analyzer",
        "Recon Scout",
        "Intel Reporter",
        "Network Analyst",
        "Memory Analyst",
        "Guardian Protocol",
        "Chrome Infiltrator",
        "Wireless Infiltrator",
        "Mobile Infiltrator",
        "RF Analyzer",
        "Signal Repeater",
        "Mission Analyst",
        "Reverse Engineer",
        # Central Core is a pure router — no claude_code needed
        "Strategic Core",
    ]

    missing = []
    for agent_name in expected_agents:
        agent = agents.get(agent_name)
        if agent is None:
            continue  # Agent might not be in registry (sub-agent)
        tool_names = _get_tool_names(agent)
        if "claude_code" not in tool_names:
            missing.append(agent_name)

    assert not missing, "Agents missing claude_code:\n" + "\n".join(f"  - {n}" for n in missing)


def test_rag_tools_are_function_tools():
    """RAG tools should be proper function tools with names."""
    from kryon.tools.knowledge import (
        get_exploit_techniques,
        get_security_tools,
        query_knowledge_base,
        search_vulnerabilities,
    )

    for tool in [query_knowledge_base, search_vulnerabilities, get_exploit_techniques, get_security_tools]:
        assert hasattr(tool, "name"), f"{tool} missing 'name' attribute — not a proper function_tool"
