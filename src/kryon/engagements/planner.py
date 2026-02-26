"""Engagement planner — generates multi-day execution plans via LLM."""

from __future__ import annotations

import json
import logging
import re

logger = logging.getLogger(__name__)

from kryon.engagements.models import (
    Engagement,
    EngagementPhase,
    PhaseType,
    PHASE_AGENT_MAP,
)

__all__ = ["generate_engagement_plan", "create_phases_from_plan"]


async def generate_engagement_plan(
    engagement: Engagement,
    rate_limiter=None,
) -> dict:
    """Generate a multi-day engagement plan using LLM + strategic context.

    Falls back to a deterministic default plan if LLM is unavailable.
    """
    try:
        plan = await _generate_llm_plan(engagement, rate_limiter)
        if plan and "days" in plan:
            return plan
    except Exception:
        logger.debug("LLM plan failed, using fallback", exc_info=True)

    return _generate_default_plan(engagement)


async def _generate_llm_plan(engagement: Engagement, rate_limiter) -> dict | None:
    """Use mission_analyst agent to generate a plan (1 LLM call)."""
    if rate_limiter:
        await rate_limiter.acquire(estimated_tokens=3000)

    # Get strategic context (local, no LLM)
    strategic_context = _get_strategic_context(engagement)

    from kryon.agents import get_agent_by_name
    from kryon.sdk.agents import Runner

    agent = get_agent_by_name("mission_analyst")

    prompt = f"""Plan a {engagement.duration_days}-day penetration testing engagement.

Targets: {', '.join(engagement.targets)}
Client: {engagement.client_name}
Objectives: {', '.join(engagement.objectives)}
Stealth: {engagement.stealth_level}
Profile: {engagement.profile}

Available phase types (use ONLY these exact values):
- reconnaissance (agent: recon_scout)
- vulnerability_assessment (agent: vuln_hunter)
- exploitation (agent: pentest_agent)
- deep_exploitation (agent: pentest_agent)
- lateral_movement (agent: network_analyst)
- persistence_testing (agent: pentest_agent)
- reporting (agent: reporter)

{strategic_context}

Output ONLY a JSON object with this exact structure (no markdown, no explanation):
{{
    "days": [
        {{
            "day": 1,
            "phases": [
                {{"phase_type": "reconnaissance", "agent_key": "recon_scout", "description": "Full network reconnaissance"}}
            ]
        }}
    ],
    "rationale": "brief explanation"
}}"""

    result = await Runner.run(agent, input=prompt, max_turns=2)
    return _parse_plan_json(result.final_output)


def _get_strategic_context(engagement: Engagement) -> str:
    """Gather local strategic context (no LLM calls)."""
    lines = []
    try:
        from kryon.tools.autonomous.strategic_planner import StrategicPlanner

        planner = StrategicPlanner()
        plan = planner.autonomous_mission_planner(
            target_network=engagement.targets[0] if engagement.targets else "unknown",
            objectives=engagement.objectives,
            constraints={
                "time_limit": engagement.duration_days * 86400,
                "stealth_level": engagement.stealth_level,
            },
            resources={},
        )
        stages = plan.get("primary_plan", {}).get("stages", [])
        if stages:
            lines.append("Strategic analysis suggests:")
            lines.append(json.dumps(stages[:5], indent=2, default=str))
    except Exception:
        logger.debug("Strategic context unavailable", exc_info=True)

    try:
        from kryon.tools.autonomous.learning_engine import get_learning_engine

        engine = get_learning_engine()
        recs = engine.get_learned_recommendations(
            target_profile={"os": "unknown", "services": []}, top_n=3
        )
        if recs.get("recommended_exploits"):
            lines.append("Historical recommendations:")
            lines.append(json.dumps(recs["recommended_exploits"][:3], indent=2, default=str))
    except Exception:
        logger.debug("Learning engine unavailable", exc_info=True)

    return "\n".join(lines) if lines else ""


def _parse_plan_json(text: str) -> dict | None:
    """Extract JSON plan from LLM output."""
    if not text:
        return None

    # Try direct JSON parse
    try:
        plan = json.loads(text)
        if "days" in plan:
            return _validate_plan(plan)
    except json.JSONDecodeError:
        pass

    # Try extracting JSON from markdown code blocks
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            plan = json.loads(match.group(1))
            if "days" in plan:
                return _validate_plan(plan)
        except json.JSONDecodeError:
            pass

    # Try finding JSON object in text
    match = re.search(r"\{[^{}]*\"days\"[^{}]*\[.*\].*\}", text, re.DOTALL)
    if match:
        try:
            plan = json.loads(match.group(0))
            if "days" in plan:
                return _validate_plan(plan)
        except json.JSONDecodeError:
            pass

    return None


def _validate_plan(plan: dict) -> dict | None:
    """Validate that plan has correct structure and valid phase types."""
    valid_types = {pt.value for pt in PhaseType}
    days = plan.get("days", [])
    if not days:
        return None

    for day in days:
        if "day" not in day or "phases" not in day:
            return None
        for phase in day["phases"]:
            pt = phase.get("phase_type", "")
            if pt not in valid_types:
                return None
            # Auto-fix agent_key if missing or wrong
            if not phase.get("agent_key") or phase["agent_key"] not in PHASE_AGENT_MAP.values():
                phase["agent_key"] = PHASE_AGENT_MAP.get(pt, "pentest_agent")

    return plan


def _generate_default_plan(engagement: Engagement) -> dict:
    """Deterministic fallback plan when LLM is unavailable."""
    d = engagement.duration_days
    days = []

    # Day 1: Reconnaissance
    days.append({
        "day": 1,
        "phases": [{
            "phase_type": "reconnaissance",
            "agent_key": "recon_scout",
            "description": "Full network reconnaissance and service enumeration",
        }],
    })

    # Day 2: Vulnerability assessment
    if d >= 2:
        days.append({
            "day": 2,
            "phases": [{
                "phase_type": "vulnerability_assessment",
                "agent_key": "vuln_hunter",
                "description": "Comprehensive vulnerability scanning and assessment",
            }],
        })

    # Middle days: exploitation + optional lateral movement
    exploit_end = d - 1 if d >= 3 else d
    if d >= 5:
        exploit_end = d - 2  # Leave room for lateral movement

    for day_num in range(3, exploit_end + 1):
        phase_type = "exploitation" if day_num == 3 else "deep_exploitation"
        days.append({
            "day": day_num,
            "phases": [{
                "phase_type": phase_type,
                "agent_key": "pentest_agent",
                "description": f"{'Initial' if day_num == 3 else 'Deep'} exploitation of discovered vulnerabilities",
            }],
        })

    if d >= 5:
        days.append({
            "day": d - 1,
            "phases": [{
                "phase_type": "lateral_movement",
                "agent_key": "network_analyst",
                "description": "Lateral movement and network pivoting",
            }],
        })

    # Last day: Reporting
    days.append({
        "day": d,
        "phases": [{
            "phase_type": "reporting",
            "agent_key": "reporter",
            "description": "Final engagement report with all findings and recommendations",
        }],
    })

    return {"days": days, "rationale": "Default plan (deterministic fallback)"}


def create_phases_from_plan(engagement: Engagement, plan: dict) -> list[EngagementPhase]:
    """Convert a plan dict into EngagementPhase objects."""
    phases = []
    for day_data in plan.get("days", []):
        day_num = day_data.get("day", 1)
        for idx, phase_data in enumerate(day_data.get("phases", [])):
            phase = EngagementPhase(
                engagement_id=engagement.id,
                phase_type=PhaseType(phase_data["phase_type"]),
                day_number=day_num,
                order_index=idx,
                agent_key=phase_data.get("agent_key", PHASE_AGENT_MAP.get(phase_data["phase_type"], "pentest_agent")),
                targets_subset=json.dumps(engagement.targets),
            )
            phases.append(phase)
    return phases
