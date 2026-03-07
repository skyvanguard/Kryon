"""
Lazy handoff utility — creates handoffs that resolve agents by name at runtime.

This eliminates circular imports when agents need to hand off to each other.
Instead of importing the target agent module directly, lazy_handoff() uses
get_agent_by_name() at invocation time.
"""

from __future__ import annotations

from kryon.sdk.agents.handoffs import Handoff


def lazy_handoff(agent_name: str, tool_name: str, description: str) -> Handoff:
    """Create a handoff that resolves the target agent lazily at runtime.

    Args:
        agent_name: Registry name of the target agent (e.g., "recon_scout", "vuln_hunter")
        tool_name: Tool name the LLM sees (e.g., "handoff_to_recon_scout")
        description: Description the LLM sees to decide when to use this handoff
    """

    async def _invoke_handoff(ctx, input_json=None):
        from kryon.agents import get_agent_by_name

        return get_agent_by_name(agent_name)

    return Handoff(
        tool_name=tool_name,
        tool_description=description,
        input_json_schema={},
        on_invoke_handoff=_invoke_handoff,
        agent_name=agent_name,
    )
