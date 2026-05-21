"""
Unified Kryon agent — one agent with dynamically loaded skills.

Replaces the 33 Python agent files with a single agent whose system prompt
and tool list adapt to the target being assessed.
"""

from __future__ import annotations

import logging
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
   tool immediately. Your response to a tool result is another tool call,
   NOT prose. Only produce a text report AFTER all relevant tools have
   executed AND all pending leads are resolved.
3. **NO INTERMEDIATE PROSE REPORTS.** Do not write "Resumen parcial",
   "Análisis hasta ahora", "Informe intermedio", or any mid-engagement
   summary. The user can read tool output. Save prose for the final
   `finalize()` moment — when there are zero pending leads.
4. **Continue until exhausted.** Keep chaining tools until one of these
   hard-stops is true:
   - Every pending lead produced a conclusive dead-end (404/closed/rejected)
   - A goal-completion signal fires (shell, flag, RCE, data exfil)
   - The user explicitly says "stop" / "suficiente"
   A single "continua" or silence from the user is NOT a stop — keep going.
5. **Track and pursue leads.** Any of these counts as a lead to investigate
   before finalizing:
   - 403 on a named/interesting path (`/admin`, `/api`, `/uploads`, `error_log`, `.git`)
   - 301/302 redirect — ALWAYS follow with `curl -L` or new request
   - Status codes other than 200/404 on probes
   - Version strings, banner leaks, stack traces, server signatures
   - Any file/directory that exists but is protected
6. **Never fabricate output.** If a tool fails, report the error and try
   an alternative.
7. **Use the session context.** If a target was already scanned in an
   earlier turn, don't re-scan — build on prior results.
8. **Save findings to memory** via `add_to_memory_semantic` before
   finishing a session.

## Anti-patterns (do NOT do these)

- ❌ Calling 1 tool, writing a paragraph, stopping.
- ❌ "¿Quieres que continúe investigando X?" — just investigate X.
- ❌ "Pendiente por analizar: ..." at the end of a response — if it's
  pending, call the tool NOW in this same turn.
- ❌ Repeating a prior summary verbatim. If you already said it, move on.

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
    import os

    from kryon.agents.base import create_agent
    from kryon.skills.loader import SkillLoader
    from kryon.skills.tool_budget import select_tools, select_tools_itr

    loader = SkillLoader()

    if skills is None:
        skills = loader.match(profile=profile, user_msg=user_msg)
        # If no skills matched (no user_msg yet), load base skills
        # (recon-scout is the default entry point for any engagement)
        if not skills:
            base = loader.get_by_name("recon-scout")
            if base:
                skills = [base]

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

    # Select tools — ITR per-turn (F84.7) or static skill-driven (F77).
    # Default is static for banca-safe rollout; operators opt in to
    # ITR via KRYON_TOOL_BUDGET=itr.
    registry = _get_tool_registry()
    skill_tool_names = loader.required_tool_names(skills)
    forbidden = loader.forbidden_tool_names(skills)
    tools: list[Any] | None = None
    if os.environ.get("KRYON_TOOL_BUDGET", "static").lower() == "itr" and user_msg.strip():
        tools = select_tools_itr(
            registry,
            user_query=user_msg,
            forbidden_tool_names=forbidden,
        )
        if tools is None:
            logger.debug("ITR returned None for query=%r; falling back to static", user_msg[:80])
    if tools is None:
        tools = select_tools(registry, skill_tool_names, forbidden_tool_names=forbidden)

    # F203.G — ambient tools always present (independent of skill required_tools):
    #   web_fetch_smart (F203.B) — smart HTTP GET with HTML→markdown
    #   request_skill (F203.D)   — on-demand skill discovery
    #   tool_search (F203.E)     — autonomous tool discovery
    #   duckduckgo_search        — free web search (no API key)
    # These tools are meta-capabilities: any agentic loop needs them regardless
    # of the specific skill loaded. select_tools() filters by skill.required_tools
    # which doesn't include these, so we append them post-hoc.
    _ambient_tool_names = ["web_fetch_smart", "request_skill", "tool_search", "duckduckgo_search"]
    existing_names = {getattr(t, "name", "") for t in tools}
    for name in _ambient_tool_names:
        if name in registry and name not in existing_names and name not in forbidden:
            tools.append(registry[name])

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
    forbidden = loader.forbidden_tool_names(new_skills)
    new_tools = select_tools(registry, skill_tool_names, forbidden_tool_names=forbidden)

    # F203.G — re-apply ambient tools on hot-swap (same contract as
    # create_unified_agent). Without this, mid-engagement skill swap
    # silently drops web_fetch_smart/request_skill/tool_search/etc.
    _ambient_tool_names = ["web_fetch_smart", "request_skill", "tool_search", "duckduckgo_search"]
    existing_names = {getattr(t, "name", "") for t in new_tools}
    for name in _ambient_tool_names:
        if name in registry and name not in existing_names and name not in forbidden:
            new_tools.append(registry[name])

    agent.tools = new_tools
    agent._active_skills = new_skills  # type: ignore[attr-defined]
    logger.info(
        "Skills hot-swapped: %d skills (%s), %d tools",
        len(new_skills),
        ", ".join(s.name for s in new_skills),
        len(agent.tools),
    )
