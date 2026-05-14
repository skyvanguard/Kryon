"""F117 — PhaseEvaluator deterministic rules.

The evaluator is invoked after every orchestrated phase to decide
whether the phase produced useful evidence and whether downstream
phases should be retried, skipped, or proceeded with.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from kryon.tools.autonomous.pentest_planner import (
    PentestPlan,
    PhaseStatus,
    PlanPhase,
)
from kryon.tools.autonomous.phase_evaluator import (
    PhaseEvaluation,
    PhaseVerdict,
    cascade_skip_dependents,
    evaluate_phase,
)


@dataclass
class _F:
    """Minimal finding shape compatible with engage.Finding +
    enterprise findings."""

    rule_id: str = ""
    severity: str = "INFO"
    message: str = ""
    title: str = ""
    description: str = ""
    evidence: str = ""
    host: str = ""


def _phase(name: str, status: PhaseStatus = PhaseStatus.COMPLETED) -> PlanPhase:
    return PlanPhase(name=name, agent_key="x", max_turns=3, status=status)


# ---------------------------------------------------------------------------
# Verdict classification
# ---------------------------------------------------------------------------


def test_failed_phase_is_inconclusive():
    phase = _phase("recon", status=PhaseStatus.FAILED)
    ev = evaluate_phase(phase, findings_before=[], findings_after=[])
    assert ev.verdict is PhaseVerdict.INCONCLUSIVE
    assert ev.quality_score == 0.0
    assert ev.recommend_retry is False
    assert ev.skip_dependents is False


def test_critical_finding_means_useful():
    phase = _phase("vuln_scan")
    before: list[Any] = []
    after = [_F(rule_id="WEB-001", severity="CRITICAL", message="RCE on /upload")]
    ev = evaluate_phase(phase, findings_before=before, findings_after=after)
    assert ev.verdict is PhaseVerdict.USEFUL
    assert ev.delta_findings == 1
    assert ev.delta_critical_high == 1
    assert ev.quality_score >= 0.7


def test_high_finding_means_useful():
    phase = _phase("vuln_scan")
    after = [_F(rule_id="WEB-010", severity="HIGH")]
    ev = evaluate_phase(phase, findings_before=[], findings_after=after)
    assert ev.verdict is PhaseVerdict.USEFUL


def test_zero_delta_and_no_signature_is_barren():
    phase = _phase("vuln_scan")
    ev = evaluate_phase(phase, findings_before=[], findings_after=[])
    assert ev.verdict is PhaseVerdict.BARREN
    assert ev.delta_findings == 0
    assert ev.quality_score == 0.0


def test_only_info_findings_without_signature_is_partial():
    phase = _phase("vuln_scan")
    # vuln_scan expects severity-bearing findings; an INFO-only delta is partial
    after = [_F(rule_id="INFO-009", severity="INFO", message="banner")]
    ev = evaluate_phase(phase, findings_before=[], findings_after=after)
    assert ev.verdict is PhaseVerdict.PARTIAL
    assert ev.recommend_retry is True
    assert 0.0 < ev.quality_score < 1.0


# ---------------------------------------------------------------------------
# Per-phase expected signatures
# ---------------------------------------------------------------------------


def test_proxmox_audit_with_pve_finding_is_useful():
    phase = _phase("proxmox_audit")
    after = [_F(rule_id="PVE-2.2.7", severity="MEDIUM", message="root@pam without 2FA")]
    ev = evaluate_phase(phase, findings_before=[], findings_after=after)
    assert ev.verdict is PhaseVerdict.USEFUL
    assert "PVE-" in ev.expected_sigs_hit


def test_proxmox_audit_without_pve_finding_is_partial():
    phase = _phase("proxmox_audit")
    # Got a finding but not from the expected family — partial signal
    after = [_F(rule_id="GEN-001", severity="LOW", message="banner")]
    ev = evaluate_phase(phase, findings_before=[], findings_after=after)
    assert ev.verdict is PhaseVerdict.PARTIAL
    assert "PVE-" in ev.expected_sigs_missed


def test_fortigate_audit_with_fgt_finding_is_useful():
    phase = _phase("fortigate_audit")
    after = [_F(rule_id="FGT-1.1", severity="HIGH")]
    ev = evaluate_phase(phase, findings_before=[], findings_after=after)
    assert ev.verdict is PhaseVerdict.USEFUL


def test_unifi_audit_with_unf_finding_is_useful():
    phase = _phase("unifi_audit")
    after = [_F(rule_id="UNF-1.2", severity="MEDIUM")]
    ev = evaluate_phase(phase, findings_before=[], findings_after=after)
    assert ev.verdict is PhaseVerdict.USEFUL


def test_ad_recon_keyword_match_is_useful():
    phase = _phase("ad_recon")
    after = [_F(rule_id="NET-002", severity="INFO", message="LDAP on port 389 detected")]
    ev = evaluate_phase(phase, findings_before=[], findings_after=after)
    assert ev.verdict is PhaseVerdict.USEFUL


def test_recon_with_open_port_finding_is_useful():
    phase = _phase("recon")
    after = [_F(rule_id="NMAP-001", severity="INFO", message="open port 22/tcp")]
    ev = evaluate_phase(phase, findings_before=[], findings_after=after)
    assert ev.verdict is PhaseVerdict.USEFUL


def test_reporting_phase_is_always_useful_when_completed():
    # reporting has no expected sigs — completion alone is success
    phase = _phase("reporting")
    ev = evaluate_phase(phase, findings_before=[], findings_after=[])
    assert ev.verdict is PhaseVerdict.USEFUL


# ---------------------------------------------------------------------------
# Skip-dependents semantics
# ---------------------------------------------------------------------------


def test_barren_recon_recommends_skip_dependents():
    phase = _phase("recon")
    ev = evaluate_phase(phase, findings_before=[], findings_after=[])
    assert ev.verdict is PhaseVerdict.BARREN
    assert ev.skip_dependents is True


def test_barren_reporting_does_not_recommend_skip_dependents():
    # reporting has no expected sigs, so it can't go barren — sanity check
    phase = _phase("reporting")
    ev = evaluate_phase(phase, findings_before=[], findings_after=[])
    assert ev.skip_dependents is False


def test_barren_proxmox_audit_does_not_cascade_skip():
    # device audits are leaf phases — their failure shouldn't cascade
    phase = _phase("proxmox_audit")
    ev = evaluate_phase(phase, findings_before=[], findings_after=[])
    assert ev.verdict is PhaseVerdict.BARREN
    assert ev.skip_dependents is False


def test_useful_phase_never_recommends_retry_or_skip():
    phase = _phase("vuln_scan")
    after = [_F(rule_id="WEB-001", severity="CRITICAL")]
    ev = evaluate_phase(phase, findings_before=[], findings_after=after)
    assert ev.recommend_retry is False
    assert ev.skip_dependents is False


# ---------------------------------------------------------------------------
# Delta semantics
# ---------------------------------------------------------------------------


def test_delta_is_difference_not_total():
    phase = _phase("vuln_scan")
    before = [_F(rule_id="OLD-001", severity="HIGH")]
    after = before + [_F(rule_id="NEW-001", severity="CRITICAL")]
    ev = evaluate_phase(phase, findings_before=before, findings_after=after)
    assert ev.delta_findings == 1
    assert ev.delta_critical_high == 1


def test_no_delta_with_old_findings_is_still_barren_for_recon():
    phase = _phase("recon")
    before = [_F(rule_id="NMAP-001", severity="INFO", message="open port 22")]
    after = list(before)  # same content, no new evidence
    ev = evaluate_phase(phase, findings_before=before, findings_after=after)
    assert ev.delta_findings == 0
    assert ev.verdict is PhaseVerdict.BARREN


# ---------------------------------------------------------------------------
# cascade_skip_dependents
# ---------------------------------------------------------------------------


def _plan_with_phases(phases: list[PlanPhase]) -> PentestPlan:
    plan = PentestPlan()
    plan.phases = phases
    return plan


def test_cascade_skips_only_pending_dependents():
    phases = [
        PlanPhase(name="recon", agent_key="recon_scout", max_turns=3, status=PhaseStatus.COMPLETED),
        PlanPhase(
            name="vuln_scan", agent_key="vuln_hunter", max_turns=3, status=PhaseStatus.PENDING, depends_on=["recon"]
        ),
        PlanPhase(
            name="exploitation",
            agent_key="pentest_agent",
            max_turns=5,
            status=PhaseStatus.PENDING,
            depends_on=["vuln_scan"],
        ),
        PlanPhase(name="reporting", agent_key="reporter", max_turns=2, status=PhaseStatus.PENDING),
    ]
    plan = _plan_with_phases(phases)

    cascaded = cascade_skip_dependents(plan, "recon")

    assert cascaded == 1  # only vuln_scan depends directly on recon
    statuses = {p.name: p.status for p in plan.phases}
    assert statuses["vuln_scan"] is PhaseStatus.SKIPPED
    assert statuses["exploitation"] is PhaseStatus.PENDING  # not transitive
    assert statuses["reporting"] is PhaseStatus.PENDING
    assert statuses["recon"] is PhaseStatus.COMPLETED


def test_cascade_skips_multiple_dependents():
    phases = [
        PlanPhase(name="recon", agent_key="r", max_turns=3, status=PhaseStatus.COMPLETED),
        PlanPhase(name="proxmox_audit", agent_key="v", max_turns=3, status=PhaseStatus.PENDING, depends_on=["recon"]),
        PlanPhase(name="fortigate_audit", agent_key="v", max_turns=3, status=PhaseStatus.PENDING, depends_on=["recon"]),
    ]
    plan = _plan_with_phases(phases)

    cascaded = cascade_skip_dependents(plan, "recon")

    assert cascaded == 2
    assert all(p.status is PhaseStatus.SKIPPED for p in plan.phases if p.name != "recon")


def test_cascade_does_not_touch_completed_or_failed():
    phases = [
        PlanPhase(name="vuln_scan", agent_key="v", max_turns=3, status=PhaseStatus.COMPLETED, depends_on=["recon"]),
        PlanPhase(name="exploitation", agent_key="e", max_turns=5, status=PhaseStatus.FAILED, depends_on=["recon"]),
    ]
    plan = _plan_with_phases(phases)

    cascaded = cascade_skip_dependents(plan, "recon")

    assert cascaded == 0
    statuses = {p.name: p.status for p in plan.phases}
    assert statuses["vuln_scan"] is PhaseStatus.COMPLETED
    assert statuses["exploitation"] is PhaseStatus.FAILED


def test_cascade_returns_zero_when_no_dependents():
    phases = [
        PlanPhase(name="recon", agent_key="r", max_turns=3, status=PhaseStatus.COMPLETED),
        PlanPhase(name="reporting", agent_key="rep", max_turns=2, status=PhaseStatus.PENDING),
    ]
    plan = _plan_with_phases(phases)

    cascaded = cascade_skip_dependents(plan, "recon")

    assert cascaded == 0
    assert plan.phases[1].status is PhaseStatus.PENDING
