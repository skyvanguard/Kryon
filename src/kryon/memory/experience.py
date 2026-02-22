"""Agent strategy learning and experience recall."""

from __future__ import annotations

from kryon.memory.models import AgentExperience
from kryon.memory.store import MemoryStore


class ExperienceManager:
    """Manage agent experience for strategy learning."""

    def __init__(self, store: MemoryStore):
        self.store = store

    def record_experience(
        self,
        agent_key: str,
        target_type: str,
        strategy: str,
        tools_effective: list[str] | None = None,
        tools_ineffective: list[str] | None = None,
        notes: str = "",
    ) -> AgentExperience:
        """Record what worked for an agent on a target type."""
        exp = AgentExperience(
            agent_key=agent_key,
            target_type=target_type,
            strategy=strategy,
            tools_effective=tools_effective or [],
            tools_ineffective=tools_ineffective or [],
            notes=notes,
        )
        return self.store.save_experience(exp)

    def recall_experience(self, agent_key: str, target_type: str = "") -> str:
        """Recall past experience as a text summary for agent context."""
        experiences = self.store.get_experience(agent_key, target_type)
        if not experiences:
            return ""

        lines = [f"Past experience for {agent_key}:"]
        for exp in experiences[:5]:  # Last 5
            lines.append(
                f"- Target type: {exp.target_type} | Strategy: {exp.strategy}"
            )
            if exp.tools_effective:
                lines.append(f"  Effective tools: {', '.join(exp.tools_effective)}")
            if exp.tools_ineffective:
                lines.append(
                    f"  Ineffective tools: {', '.join(exp.tools_ineffective)}"
                )
            if exp.notes:
                lines.append(f"  Notes: {exp.notes}")
        return "\n".join(lines)
