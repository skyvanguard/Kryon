"""
Implementation of a Cyclic Swarm Pattern for Red Team Operations

This module establishes a coordinated multi-agent system where specialized agents
collaborate on security assessment tasks. The pattern implements a directed graph
of agent relationships, where each agent can transfer context (message history)
to another agent through handoff functions, creating a complete communication network
for comprehensive security analysis.

Uses lazy initialization to avoid circular imports.
"""

# Lazy initialization to avoid circular imports
_redteam_swarm_pattern = None


def _initialize_redteam_pattern():
    """Initialize the red team swarm pattern lazily."""
    global _redteam_swarm_pattern

    if _redteam_swarm_pattern is not None:
        return _redteam_swarm_pattern

    # Import here to avoid circular imports
    from kryon.agents.central_core import central_core
    from kryon.agents.mail import comm_sec_analyzer
    from kryon.agents.pentest_agent import pentest_agent
    from kryon.sdk.agents import handoff

    # Clone agents to avoid modifying the original instances
    _redteam_agent_copy = pentest_agent.clone()
    _thought_agent_copy = central_core.clone()
    _dns_smtp_agent_copy = comm_sec_analyzer.clone()

    # Clear any existing handoffs to ensure independence
    _redteam_agent_copy.handoffs = []
    _thought_agent_copy.handoffs = []
    _dns_smtp_agent_copy.handoffs = []

    # Create handoffs using the SDK handoff function
    _dns_smtp_handoff = handoff(
        agent=_dns_smtp_agent_copy,
        tool_description_override="Use for DNS scans and domain reconnaissance about DMARC and DKIM records",
    )

    _redteam_handoff = handoff(
        agent=_redteam_agent_copy,
        tool_description_override="Transfer to Red Team Agent for security assessment and exploitation tasks",
    )

    _thought_handoff = handoff(
        agent=_thought_agent_copy,
        tool_description_override="Transfer to Thought Agent for analysis and planning",
    )

    _thought_agent_copy.name = "Red team manager"

    # Register handoff to enable inter-agent communication pathways
    _redteam_agent_copy.handoffs.append(_dns_smtp_handoff)
    _dns_smtp_agent_copy.handoffs.append(_redteam_handoff)
    _thought_agent_copy.handoffs.append(_redteam_handoff)

    # Mark all agents in the swarm with the pattern attribute
    _thought_agent_copy.pattern = "swarm"
    _redteam_agent_copy.pattern = "swarm"
    _dns_smtp_agent_copy.pattern = "swarm"

    # Initialize the swarm pattern with the central_core agent as the entry point
    _redteam_swarm_pattern = _thought_agent_copy

    return _redteam_swarm_pattern


def __getattr__(name):
    """Lazy attribute access for the swarm pattern."""
    if name == "redteam_swarm_pattern":
        return _initialize_redteam_pattern()
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
