"""Phase executor — runs individual engagement phases."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Callable

from kryon.engagements.models import (
    Engagement,
    EngagementPhase,
    PhaseType,
)
from kryon.memory.store import MemoryStore

__all__ = ["execute_phase"]

_DEFAULT_PHASE_MAX_HOURS = 4.0
_DEFAULT_AGENT_MAX_TURNS = 5


async def execute_phase(
    phase: EngagementPhase,
    engagement: Engagement,
    store: MemoryStore,
    rate_limiter=None,
    emit_event: Callable | None = None,
) -> EngagementPhase:
    """Execute a single engagement phase.

    Reuses EnterpriseOrchestrator for recon/vuln phases and
    Runner.run() for exploitation/agent phases.
    """
    now = datetime.now(timezone.utc).isoformat()
    store.update_engagement_phase(phase.id, status="running", started_at=now, progress=0.0)
    store.update_engagement(engagement.id, current_phase_id=phase.id)

    if emit_event:
        emit_event(
            "phase_start",
            {
                "phase_id": phase.id,
                "phase_type": phase.phase_type.value,
                "agent_key": phase.agent_key,
                "day_number": phase.day_number,
            },
        )

    try:
        if phase.phase_type in (PhaseType.RECONNAISSANCE, PhaseType.VULNERABILITY_ASSESSMENT):
            await _run_orchestrator_phase(phase, engagement, store, rate_limiter, emit_event)
        elif phase.phase_type == PhaseType.REPORTING:
            await _run_reporting_phase(phase, engagement, store, emit_event)
        else:
            await _run_agent_phase(phase, engagement, store, rate_limiter, emit_event)

        now = datetime.now(timezone.utc).isoformat()
        store.update_engagement_phase(phase.id, status="completed", completed_at=now, progress=1.0)

        if emit_event:
            emit_event("phase_complete", {"phase_id": phase.id, "findings_count": phase.findings_count})

    except Exception as exc:
        store.update_engagement_phase(phase.id, status="failed", error=str(exc))
        if emit_event:
            emit_event("phase_error", {"phase_id": phase.id, "error": str(exc)})
        raise

    return store.get_engagement_phase(phase.id)


async def _run_orchestrator_phase(
    phase: EngagementPhase,
    engagement: Engagement,
    store: MemoryStore,
    rate_limiter,
    emit_event: Callable | None,
) -> None:
    """Use EnterpriseOrchestrator for recon/vuln phases."""
    from kryon.tools.autonomous.enterprise_orchestrator import EnterpriseOrchestrator

    targets = json.loads(phase.targets_subset) or engagement.targets
    profile_map = {
        PhaseType.RECONNAISSANCE: "quick",
        PhaseType.VULNERABILITY_ASSESSMENT: "standard",
    }

    def _on_progress(progress):
        store.update_engagement_phase(
            phase.id,
            progress=progress.phase_progress,
            findings_count=progress.findings_count,
        )
        if emit_event:
            emit_event(
                "phase_update",
                {
                    "phase_id": phase.id,
                    "progress": progress.phase_progress,
                    "findings_count": progress.findings_count,
                    "status_msg": progress.log_messages[-1] if progress.log_messages else "",
                },
            )

    orch = EnterpriseOrchestrator(
        scope=targets,
        client_name=engagement.client_name,
        profile=profile_map.get(phase.phase_type, "standard"),
        max_time_hours=_DEFAULT_PHASE_MAX_HOURS,
        stealth_level=engagement.stealth_level,
        rate_limiter=rate_limiter,
        progress_callback=_on_progress,
    )

    result = await orch.run()

    findings_count = result.get("findings_count", 0) if isinstance(result, dict) else 0
    store.update_engagement_phase(
        phase.id,
        scan_id=orch.progress.scan_id,
        findings_count=findings_count,
    )
    _update_engagement_totals(engagement.id, store)


async def _run_agent_phase(
    phase: EngagementPhase,
    engagement: Engagement,
    store: MemoryStore,
    rate_limiter,
    emit_event: Callable | None,
) -> None:
    """Execute a phase using an agent via Runner."""
    if rate_limiter:
        await rate_limiter.acquire(estimated_tokens=2000)

    from kryon.agents import get_agent_by_name
    from kryon.sdk.agents import Runner

    agent = get_agent_by_name(phase.agent_key)
    prior_context = _gather_prior_findings(engagement.id, store)

    prompt = f"""Execute {phase.phase_type.value} phase on authorized targets.

Targets: {json.loads(phase.targets_subset) or engagement.targets}
Client: {engagement.client_name} (authorized engagement)
Stealth level: {engagement.stealth_level}

Previous findings from this engagement:
{prior_context}

Perform thorough {phase.phase_type.value} and report all findings in detail."""

    if emit_event:
        emit_event("log", {"message": f"Running {phase.agent_key} for {phase.phase_type.value}..."})

    await Runner.run(agent, input=prompt, max_turns=_DEFAULT_AGENT_MAX_TURNS)

    store.update_engagement_phase(phase.id, progress=1.0)

    if emit_event:
        emit_event("log", {"message": f"Agent {phase.agent_key} completed"})


async def _run_reporting_phase(
    phase: EngagementPhase,
    engagement: Engagement,
    store: MemoryStore,
    emit_event: Callable | None,
) -> None:
    """Generate final engagement report."""
    if emit_event:
        emit_event("log", {"message": "Generating final engagement report..."})

    # Collect all findings from engagement phases
    phases = store.get_engagement_phases(engagement.id)
    all_scan_ids = [p.scan_id for p in phases if p.scan_id]

    all_findings = []
    for scan_id in all_scan_ids:
        findings = store.get_findings(scan_id)
        all_findings.extend(findings)

    try:
        from kryon.reporting.generator import ReportGenerator
        from kryon.reporting.models import ReportConfig, ReportType

        config = ReportConfig(
            report_type=ReportType.TECHNICAL,
            client_name=engagement.client_name,
            target_scope=", ".join(engagement.targets[:10]),
        )

        gen = ReportGenerator()
        html = gen.generate([json.loads(f.finding_json) for f in all_findings if f.finding_json], config)

        from kryon.reporting.export import save_report

        path = save_report(html, engagement.client_name, "engagement")
        store.update_engagement_phase(
            phase.id,
            checkpoint_json=json.dumps({"report_path": str(path)}),
        )

        if emit_event:
            emit_event("log", {"message": f"Report saved: {path}"})
    except Exception as exc:
        if emit_event:
            emit_event("log", {"message": f"Report generation: {exc}"})
        # Non-fatal — mark as complete with note
        store.update_engagement_phase(
            phase.id,
            checkpoint_json=json.dumps({"report_error": str(exc)}),
        )

    store.update_engagement_phase(phase.id, progress=1.0)


def _gather_prior_findings(engagement_id: str, store: MemoryStore) -> str:
    """Gather context from prior phases for use in exploitation prompts."""
    phases = store.get_engagement_phases(engagement_id)
    completed = [p for p in phases if p.status.value == "completed" and p.scan_id]

    if not completed:
        return "No prior findings yet."

    lines = []
    for p in completed:
        findings = store.get_findings(p.scan_id)
        lines.append(f"Phase {p.phase_type.value} (day {p.day_number}): {len(findings)} findings")
        for f in findings[:5]:
            try:
                data = json.loads(f.finding_json) if f.finding_json else {}
                title = data.get("title", "Unknown")
                sev = data.get("severity", "unknown")
                lines.append(f"  - [{sev}] {title}")
            except json.JSONDecodeError:
                pass

    return "\n".join(lines) if lines else "No prior findings yet."


def _update_engagement_totals(engagement_id: str, store: MemoryStore):
    """Recalculate total findings across all phases."""
    phases = store.get_engagement_phases(engagement_id)
    total = sum(p.findings_count for p in phases)
    store.update_engagement(engagement_id, total_findings=total)
