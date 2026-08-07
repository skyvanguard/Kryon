"""
Lazy handoff utility — creates handoffs that resolve agents by name at runtime.

This eliminates circular imports when agents need to hand off to each other.
Instead of importing the target agent module directly, lazy_handoff() uses
get_agent_by_name() at invocation time.
"""

from __future__ import annotations

from typing import Any

from kryon.sdk.agents.handoffs import Handoff

# --- Handoff Briefing Schemas ---
# Structured data the LLM must provide when escalating between agents.

HANDOFF_BRIEFING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings_summary": {
            "type": "string",
            "description": "Brief summary of what was discovered — key findings, vulnerabilities, IOCs, or progress so far.",
        },
        "recommended_action": {
            "type": "string",
            "description": "Suggested next step for the receiving agent (optional).",
        },
    },
    "required": ["findings_summary"],
    "additionalProperties": False,
}

ROUTER_HANDOFF_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "task_description": {
            "type": "string",
            "description": "Clear description of the task to delegate to this specialist agent.",
        },
    },
    "required": ["task_description"],
    "additionalProperties": False,
}


def lazy_handoff(
    agent_name: str,
    tool_name: str,
    description: str,
    *,
    schema: dict[str, Any] | None = None,
) -> Handoff:
    """Create a handoff that resolves the target agent lazily at runtime.

    Args:
        agent_name: Registry name of the target agent (e.g., "recon_scout", "vuln_hunter")
        tool_name: Tool name the LLM sees (e.g., "handoff_to_recon_scout")
        description: Description the LLM sees to decide when to use this handoff
        schema: JSON schema for the handoff input. Defaults to HANDOFF_BRIEFING_SCHEMA.
    """
    input_schema = schema if schema is not None else HANDOFF_BRIEFING_SCHEMA

    async def _invoke_handoff(ctx, input_json=None):
        from kryon.agents import get_agent_by_name

        return get_agent_by_name(agent_name)

    return Handoff(
        tool_name=tool_name,
        tool_description=description,
        input_json_schema=input_schema,
        on_invoke_handoff=_invoke_handoff,
        agent_name=agent_name,
        strict_json_schema=False,
    )
