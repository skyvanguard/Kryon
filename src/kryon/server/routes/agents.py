"""Agent listing and detail endpoints."""

from fastapi import APIRouter, Depends, HTTPException

from kryon.server.auth import require_api_key
from kryon.server.models import AgentDetail, AgentSummary

router = APIRouter(tags=["agents"], dependencies=[Depends(require_api_key)])


def _agent_tools(agent) -> list[str]:
    tools = getattr(agent, "tools", None) or []
    return [getattr(t, "name", str(t)) for t in tools]


def _agent_handoffs(agent) -> list[str]:
    handoffs = getattr(agent, "handoffs", None) or []
    names: list[str] = []
    for h in handoffs:
        if hasattr(h, "agent_name"):
            names.append(h.agent_name)
        elif hasattr(h, "name"):
            names.append(h.name)
        else:
            names.append(str(h))
    return names


def _agent_model(agent) -> str | None:
    model = getattr(agent, "model", None)
    if model is None:
        return None
    if isinstance(model, str):
        return model
    return getattr(model, "model", str(model))


@router.get("/agents", response_model=list[AgentSummary])
async def list_agents() -> list[AgentSummary]:
    """List all available agents (deduplicated, no aliases)."""
    from kryon.agents import get_available_agents

    agents = get_available_agents()
    result = []
    for key, agent in sorted(agents.items()):
        category = "pattern" if hasattr(agent, "pattern_type") else "agent"
        result.append(
            AgentSummary(
                key=key,
                name=getattr(agent, "name", key),
                description=getattr(agent, "description", None),
                category=category,
            )
        )
    return result


@router.get("/agents/{key}", response_model=AgentDetail)
async def get_agent(key: str) -> AgentDetail:
    """Get detailed information about a specific agent."""
    from kryon.agents import get_available_agents

    agents = get_available_agents()
    agent = agents.get(key)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{key}' not found")

    input_guards = getattr(agent, "input_guardrails", None) or []
    output_guards = getattr(agent, "output_guardrails", None) or []

    return AgentDetail(
        key=key,
        name=getattr(agent, "name", key),
        description=getattr(agent, "description", None),
        tools=_agent_tools(agent),
        handoffs=_agent_handoffs(agent),
        model=_agent_model(agent),
        has_guardrails=bool(input_guards or output_guards),
    )
