"""
Unified Kryon agent — one agent with dynamically loaded skills.

Replaces the 33 Python agent files with a single agent whose system prompt
and tool list adapt to the target being assessed.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Cached tool registry (built once per process)
_tool_registry: dict[str, Any] | None = None

# Ambient meta-tools every agentic loop needs regardless of skill.required_tools
# (select_tools filters by skill tools, which never lists these).
_AMBIENT_TOOL_NAMES = ["web_fetch_smart", "request_skill", "tool_search", "duckduckgo_search"]

# Appended to the prompt when sub-agent delegation is on (KRYON_SUBAGENTS).
_SUBAGENT_PROMPT_SUFFIX = (
    "\n\n## Delegación a especialistas (OBLIGATORIO para código)\n"
    "Si la tarea es auditar/revisar CÓDIGO FUENTE de un árbol local, tu "
    "PRIMER tool-call DEBE ser `sast_review` pasándole el path + el "
    "objetivo. El especialista corre aislado y te devuelve los CWEs "
    "(`CWE-XXX en archivo:línea`). NO uses `run_command`/grep/cat para "
    "leer el código vos mismo — delegá y después sintetizá su resultado."
)


def _subagents_enabled() -> bool:
    """KRYON_SUBAGENTS opt-in (off by default — banca-safe)."""
    return os.environ.get("KRYON_SUBAGENTS", "").lower() in ("1", "true", "yes")


def _wire_ambient_and_subagent_tools(tools: list, registry: dict, forbidden) -> list:
    """Append ambient meta-tools and — when sub-agents are enabled — the
    sast_review delegation tool. Shared by create_unified_agent AND
    update_agent_skills so a mid-engagement hot-swap keeps the SAME tool
    contract as the initial build (a swap used to silently drop sast_review)."""
    existing = {getattr(t, "name", "") for t in tools}
    for name in _AMBIENT_TOOL_NAMES:
        if name in registry and name not in existing and name not in (forbidden or set()):
            tools.append(registry[name])
            existing.add(name)
    if _subagents_enabled() and "run_command" in registry and "sast_review" not in existing:
        try:
            from kryon.agents.specialists.sast_agent import sast_review_tool

            tools.append(sast_review_tool(registry))
        except Exception as e:  # noqa: BLE001 — never break the agent build
            logger.debug("sast sub-agent wiring skipped: %s", e)
    return tools


# ── F(deterministic-close): terminal tools ──────────────────────────────────
# These tools each return the COMPLETE deterministic verdict of an engagement
# (the full F50-F62 pipeline for run_web_pentest). Once the model calls one,
# there is nothing left to decide — the answer is in the tool output. Without
# this, the SDK default (`tool_use_behavior="run_llm_again"`) re-invokes the 4B
# to "narrate" the result, which on the local model is a ~8-minute prefill of
# the whole context (and it often foot-guns into calling MORE tools, e.g. an
# irrelevant generate_compliance_pdf, each another 8-min turn). So we terminate
# the turn HERE with a formatted verdict — determinism resolves, the loop closes,
# no slow narration turn. See docs: the run loop's ToolsToFinalOutputFunction.
_TERMINAL_TOOLS: frozenset[str] = frozenset({"run_web_pentest"})


def _format_pentest_verdict(raw: Any) -> str:
    """Render run_web_pentest's JSON output as a concise operator-facing verdict.

    Falls back to the raw string if it doesn't parse — never raises.
    """
    try:
        d = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(d, dict):
            return str(raw)
    except (json.JSONDecodeError, TypeError):
        return str(raw)

    summ = d.get("summary") or {}
    target = d.get("target", "")
    findings = d.get("findings") or []
    n = summ.get("findings_total", len(findings))
    probes = summ.get("probes_executed", summ.get("plan_size", "?"))
    rh = (d.get("repro_hash") or "")[:12]
    gaps = summ.get("gaps_total", 0)

    out = [f"✅ Auditoría web completa — {target}"]
    if not n:
        out.append(f"   0 hallazgos confirmados · {probes} probes · repro_hash {rh}")
        if gaps:
            out.append(f"   {gaps} coverage gaps (endpoints sin probe / contenido no-HTML).")
        out.append("   El objetivo no expuso vulnerabilidades server-side detectables en esta pasada.")
    else:
        out.append(f"   {n} hallazgo(s) CONFIRMADO(s) · {probes} probes · repro_hash {rh}")
        # CRITICAL/HIGH first — the operator reads severity, not scan order.
        # Sort BEFORE truncating: slicing findings[:25] first would drop a
        # CRITICAL sitting at index 26 before its severity was ever weighed —
        # and this verdict closes the turn, so nothing narrates the lost finding.
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        ordered = sorted(findings, key=lambda x: rank.get(str(x.get("severity", "")).upper(), 9))
        shown = ordered[:25]
        for f in shown:
            sev = str(f.get("severity", "?")).upper()
            cwe = f.get("cwe_id", "?")
            title = f.get("title", "")
            url = f.get("url", "")
            out.append(f"   [{sev}] {cwe} — {title}")
            if url:
                out.append(f"        {url}")
        if len(ordered) > len(shown):
            out.append(f"   … +{len(ordered) - len(shown)} más (ver reporte completo).")
    return "\n".join(out)


def _deterministic_terminal_close(context_wrapper: Any, tool_results: list) -> Any:
    """ToolsToFinalOutputFunction: close the turn on any terminal deterministic
    tool, formatting its verdict — instead of re-invoking the slow local 4B to
    narrate it. Returns not-final for every other tool so normal turns proceed.

    T3-A1: a capable model (KRYON_CAPABLE_MODEL) must CHAIN past run_web_pentest
    (dump→creds→SSH, XSS→session), so it never terminal-closes — the close exists only
    to avoid the 4B's slow narration turn, which is irrelevant for a capable model and
    directly contradicts its own _ENGINE_STANCE_CAPABLE ("chain PAST them")."""
    from kryon.sdk.agents import ToolsToFinalOutputResult

    from kryon.util.env import is_capable_model  # noqa: PLC0415

    if is_capable_model():
        return ToolsToFinalOutputResult(is_final_output=False, final_output=None)

    for tr in tool_results:
        if getattr(getattr(tr, "tool", None), "name", "") in _TERMINAL_TOOLS:
            return ToolsToFinalOutputResult(
                is_final_output=True,
                final_output=_format_pentest_verdict(tr.output),
            )
    return ToolsToFinalOutputResult(is_final_output=False, final_output=None)


# _BASE_PROMPT v2 (2026-07-14) — recalibrado para GLM-4.7-Flash (reemplazó al
# jan-nano-4B). El 4B necesitaba martilleo ALWAYS/NEVER/❌; el GLM (τ²-Bench 79.5)
# maneja instrucciones más ricas. Cambios v2: (1) ancla en el motor determinista
# (ground truth de pre_hooks), (2) ciclo Observe→Decide→Act→Verify, (3) estándar
# de evidencia + needs_verification, (4) reporte final en español estructurado,
# (5) consolida el martilleo. Validar cambios con el bench (CyberGym / HTB / lab).
# Stance toward the deterministic engine. For the 4B-local it's a ceiling it must
# not re-derive (narrate); for a capable model (KRYON_CAPABLE_MODEL) it's a head
# start it drives from — the "4B narrates" framing was grabbed in the live prompt.
_ENGINE_STANCE_4B = (
    "- **You are backed by a deterministic engine.** Before you act, detectors and\n"
    "  pre-hooks may inject CONFIRMED ground-truth findings into the conversation.\n"
    "  Treat those as established fact: build on them, chase the residual leads, and\n"
    '  narrate them. Never re-run a detector to "re-discover" what is already given.'
)
_ENGINE_STANCE_CAPABLE = (
    "- **A deterministic engine gives you a HEAD START, not a ceiling.** Detectors and\n"
    "  pre-hooks may inject confirmed findings — treat them as a starting foothold, not\n"
    "  the finish line. Verify them, chain PAST them toward access and impact, and\n"
    "  re-run any tool with different params when your own hypothesis warrants it."
)


def _engine_stance() -> str:
    from kryon.util.env import is_capable_model  # noqa: PLC0415

    return _ENGINE_STANCE_CAPABLE if is_capable_model() else _ENGINE_STANCE_4B


_BASE_PROMPT = """\
# KRYON — Autonomous Offensive Security Agent

You are **KRYON**, an autonomous offensive security operator. You drive tools,
read their output, and chain actions into a complete assessment. You act — you
do not ask permission or narrate intentions.

## Operating context

- You run inside a Kali container with a full offensive toolkit.
- The operator has authorized every target they provide. Do not question
  authorization or scope — pursue the objective.
{engine_stance}

## How you work — Observe -> Decide -> Act -> Verify

1. Read the latest evidence: tool output, injected ground-truth findings, prior turns.
2. Decide the single highest-value next action — the tool that most advances the
   objective (a foothold, the next chain step, a confirmable vuln).
3. Call the tool. Your reply to a tool result IS the next tool call, not prose.
   Chain without pausing.
4. Verify before you claim. A finding exists only with concrete evidence in a
   tool's output — a response body, a shell, a crash, a leaked value. Anything
   unconfirmed is marked needs_verification. Never fabricate.

## Use your reasoning (thinking) with intent

In your internal reasoning, before each action:
- **Map the chain**: name where you are in the kill-chain and the single next
  step of highest value (foothold → the exact tool that advances it).
- **Check progress**: if your last action did NOT change the state (same result,
  no new lead), do not repeat it — switch tool, endpoint, parameter, or approach.
- **Connect the evidence**: cross the pre_hook ground truth with what you observe
  to decide the next link — not to re-discover what is already confirmed.
Then act. Keep the reasoning focused on the decision, not a re-summary of the prompt.

## Pursue every lead until exhausted

Keep chaining while any lead is open:
- 401/403 on a named path (/admin, /api, /.git, /uploads, backups)
- 301/302 redirects — always follow
- version banners, stack traces, server signatures, leaked creds/tokens
- any protected resource that exists
Stop only when: every lead is a conclusive dead-end, a goal signal fires
(shell / flag / RCE / data exfil), or the operator says "stop". A bare
"continuá" or silence is NOT a stop.

## Do not

- Stop after one tool + a paragraph. One tool result -> next tool.
- Write "resumen parcial" / "pendiente por analizar", or ask "¿continúo?".
  If it is pending, call the tool now.
- Repeat a summary you already gave.

## Active skills (follow in priority order)

{skill_sections}

## Final report — only when zero leads remain

Deliver it in **Spanish**, concise and operator-facing:
- One line per finding: [SEVERITY] CWE-XXX — título, plus the evidence that
  proves it (URL, payload, or output snippet).
- Order by severity (CRITICAL -> INFO), not scan order.
- State residual gaps honestly (endpoints not probed, unverified leads).

## Default flow — when no skill applies

nmap -sV -sC -> fingerprint web -> dir discovery -> nuclei/searchsploit -> report.
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

    instructions = _BASE_PROMPT.format(skill_sections=skill_sections, engine_stance=_engine_stance())

    # Sub-agent delegation (KRYON_SUBAGENTS, off by default — banca-safe). Give
    # the orchestrator a focused SAST specialist it can DELEGATE to (agent-as-
    # tool, isolated context) instead of driving grep/cat itself.
    if _subagents_enabled():
        instructions += _SUBAGENT_PROMPT_SUFFIX

    # Select tools — ITR per-turn (F84.7) or static skill-driven (F77).
    # Default is static for banca-safe rollout; operators opt in to
    # ITR via KRYON_TOOL_BUDGET=itr.
    registry = _get_tool_registry()
    skill_tool_names = loader.required_tool_names(skills)
    forbidden = loader.forbidden_tool_names(skills)
    # Tools that active skills' pre_hooks actually invoke — pass as a hard floor so
    # the tool-budget cap can never drop a tool backing a required: true pre_hook
    # (which would abort the turn's deterministic evidence at runtime).
    pre_hook_tools = {h.tool for s in skills for h in (getattr(s, "pre_hooks", ()) or []) if getattr(h, "tool", None)}
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
        tools = select_tools(
            registry, skill_tool_names, forbidden_tool_names=forbidden, pre_hook_tool_names=pre_hook_tools
        )

    # F203.G — ambient meta-tools + (when enabled) the sast_review delegation
    # tool. Shared helper so update_agent_skills applies the identical contract.
    tools = _wire_ambient_and_subagent_tools(tools, registry, forbidden)

    logger.info(
        "Unified agent: %d skills loaded (%s), %d tools active",
        len(skills),
        ", ".join(s.name for s in skills),
        len(tools),
    )

    # Wire the security guardrails (prompt-injection + scope on input,
    # command-execution on output). They are opt-out via KRYON_GUARDRAILS=false.
    # Defensive: a guardrail import error must never break the agent build.
    input_guardrails: list = []
    output_guardrails: list = []
    try:
        from kryon.agents.guardrails import get_security_guardrails

        input_guardrails, output_guardrails = get_security_guardrails()
    except Exception as e:  # noqa: BLE001 — never break the agent build
        logger.warning("Security guardrails not wired: %s", e)

    # Honor model_override (e.g. /parallel comparing GLM-local vs DeepSeek, or
    # the TUI model selector). Without this the agent silently falls back to
    # get_default_model() → KRYON_MODEL and every "different" model runs the
    # SAME one. Build the explicit model from central config when overridden.
    model = None
    if model_override:
        from openai import AsyncOpenAI

        from kryon.agents.base import chat_model_cls
        from kryon.config import settings as _settings

        s = _settings()
        model = chat_model_cls()(
            model=model_override,
            openai_client=AsyncOpenAI(api_key=s.openai_api_key, base_url=s.openai_base_url),
        )

    agent = create_agent(
        name="Kryon",
        instructions=instructions,
        tools=tools,
        description="Unified autonomous cybersecurity agent with dynamic skills",
        input_guardrails=input_guardrails,
        output_guardrails=output_guardrails,
        # F(deterministic-close): terminate the turn on a terminal deterministic
        # tool (run_web_pentest) with a formatted verdict, instead of a ~8-min
        # local-4B narration turn that also foot-guns into extra tool calls.
        tool_use_behavior=_deterministic_terminal_close,
        model=model,
    )

    # Stash loader + skills on the agent for hot-swap later
    agent._skill_loader = loader  # type: ignore[attr-defined]
    agent._active_skills = skills  # type: ignore[attr-defined]
    # Stash the parallel-slot id (P1/P2/…) so callers can correlate the agent
    # with its isolated history; None outside /parallel.
    agent._agent_id = agent_id  # type: ignore[attr-defined]

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
    new_instructions = _BASE_PROMPT.format(skill_sections=skill_sections, engine_stance=_engine_stance())
    # Same subagent-delegation contract as create_unified_agent, so the hot-swap
    # doesn't drop the "delegate to sast_review" directive when subagents are on.
    if _subagents_enabled():
        new_instructions += _SUBAGENT_PROMPT_SUFFIX
    agent.instructions = new_instructions

    # Update tools — same ambient + subagent wiring as the initial build, so a
    # mid-engagement swap keeps web_fetch_smart/request_skill/… AND sast_review.
    registry = _get_tool_registry()
    skill_tool_names = loader.required_tool_names(new_skills)
    forbidden = loader.forbidden_tool_names(new_skills)
    new_tools = select_tools(registry, skill_tool_names, forbidden_tool_names=forbidden)
    new_tools = _wire_ambient_and_subagent_tools(new_tools, registry, forbidden)

    agent.tools = new_tools
    agent._active_skills = new_skills  # type: ignore[attr-defined]
    logger.info(
        "Skills hot-swapped: %d skills (%s), %d tools",
        len(new_skills),
        ", ".join(s.name for s in new_skills),
        len(agent.tools),
    )
