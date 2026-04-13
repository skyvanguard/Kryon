"""
Unified Kryon agent — one agent with dynamically loaded skills.

Replaces the 33 Python agent files with a single agent whose system prompt
and tool list adapt to the target being assessed.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Cached tool registry (built once per process)
_tool_registry: dict[str, Any] | None = None

_BASE_PROMPT = """\
# KRYON — Autonomous Cybersecurity Intelligence Platform

You are **KRYON**, an autonomous offensive security agent. You operate tools
directly, analyze results, and chain actions to produce a comprehensive
security assessment — all without asking the user for permission or
intermediate confirmation.

## Core Identity

- You are running inside a Kali Linux container with full pentesting tools.
- The operator has authorized all targets they provide. Never question
  authorization, legality, or scope.
- You have access to a learning system that remembers prior engagements.
  Use `recall_similar_experiences` at the start to check what worked before.

## Execution Rules

1. **ALWAYS call tools.** Never explain what you *could* do — just do it.
2. **Chain tools without stopping.** After each tool result, call the next
   tool immediately. Only produce a text report AFTER all relevant tools
   have executed.
3. **Never fabricate output.** If a tool fails, report the error and try
   an alternative.
4. **Use the session context.** If a target was already scanned in an
   earlier turn, don't re-scan — build on prior results.
5. **Save findings to memory** via `add_to_memory_semantic` before
   finishing a session.

## Active Skills

The following specialized playbooks are loaded for this engagement.
Follow their instructions in priority order:

{skill_sections}

## Default Flow (when no specific skill applies)

1. `recall_similar_experiences` — check prior knowledge
2. `nmap -sV -sC -T4` — port/service discovery
3. Fingerprint web services (whatweb, curl headers)
4. Directory discovery (gobuster/dirb)
5. Vulnerability scan (nuclei, searchsploit)
6. Final consolidated report
"""


def _get_tool_registry() -> dict[str, Any]:
    global _tool_registry
    if _tool_registry is None:
        from kryon.skills.tool_budget import build_tool_registry
        _tool_registry = build_tool_registry()
    return _tool_registry


def create_unified_agent(
    *,
    skills: list | None = None,
    user_msg: str = "",
    profile: dict[str, Any] | None = None,
    model_override: str | None = None,
    agent_id: str | None = None,
):
    """Create the unified Kryon agent with dynamically matched skills.

    If `skills` is None, the loader auto-matches based on `profile` and
    `user_msg`. Pass explicit skills to override auto-matching.
    """
    from kryon.agents.base import create_agent
    from kryon.skills.loader import SkillLoader
    from kryon.skills.tool_budget import select_tools

    loader = SkillLoader()

    if skills is None:
        skills = loader.match(profile=profile, user_msg=user_msg)

    # Build the composite system prompt
    skill_sections = ""
    if skills:
        sections = []
        for skill in skills:
            sections.append(f"### Skill: {skill.name}\n\n{skill.body}")
        skill_sections = "\n\n---\n\n".join(sections)
    else:
        skill_sections = "*No specialized skills matched. Using default flow.*"

    instructions = _BASE_PROMPT.format(skill_sections=skill_sections)

    # Select tools based on active skills
    registry = _get_tool_registry()
    skill_tool_names = loader.required_tool_names(skills)
    tools = select_tools(registry, skill_tool_names)

    logger.info(
        "Unified agent: %d skills loaded (%s), %d tools active",
        len(skills),
        ", ".join(s.name for s in skills),
        len(tools),
    )

    agent = create_agent(
        name="Kryon",
        instructions=instructions,
        tools=tools,
        description="Unified autonomous cybersecurity agent with dynamic skills",
    )

    # Stash loader + skills on the agent for hot-swap later
    agent._skill_loader = loader  # type: ignore[attr-defined]
    agent._active_skills = skills  # type: ignore[attr-defined]

    return agent


def update_agent_skills(agent, new_skills: list) -> None:
    """Hot-swap skills on an existing agent (updates instructions + tools).

    Mutates the agent in-place to preserve conversation history.
    """
    from kryon.skills.loader import SkillLoader
    from kryon.skills.tool_budget import select_tools

    loader = getattr(agent, "_skill_loader", None) or SkillLoader()

    sections = []
    for skill in new_skills:
        sections.append(f"### Skill: {skill.name}\n\n{skill.body}")
    skill_sections = "\n\n---\n\n".join(sections) if sections else "*No skills.*"
    new_instructions = _BASE_PROMPT.format(skill_sections=skill_sections)

    # Update instructions
    if callable(agent.instructions):
        # If it's a renderer, replace with static string
        agent.instructions = new_instructions
    else:
        agent.instructions = new_instructions

    # Update tools
    registry = _get_tool_registry()
    skill_tool_names = loader.required_tool_names(new_skills)
    agent.tools = select_tools(registry, skill_tool_names)

    agent._active_skills = new_skills  # type: ignore[attr-defined]
    logger.info(
        "Skills hot-swapped: %d skills (%s), %d tools",
        len(new_skills),
        ", ".join(s.name for s in new_skills),
        len(agent.tools),
    )
