"""F117 — Per-phase meta-evaluator.

After each phase of an orchestrated engagement, the planner asks:
*did this phase actually produce useful evidence?* The legacy plan
adapter (`PentestPlanner.adapt_plan`) reasons over finding *content*
to inject or skip downstream phases, but it cannot distinguish
"phase ran and found nothing" from "phase ran and found exactly what
this kind of phase is supposed to find". This evaluator closes that
gap with deterministic rules — no LLM critique here, that is a
separate layer that can be added once the deterministic baseline is
trusted.

Verdicts:

- ``USEFUL``       : phase emitted high-severity findings OR matched
                     its expected signature set. Continue plan.
- ``PARTIAL``      : phase emitted only low-severity findings, or
                     missed expected signatures. Recommend one retry.
- ``BARREN``       : phase emitted no new findings AND missed every
                     expected signature. If the phase is a gating
                     phase (recon, vuln_scan, exploitation), recommend
                     skipping dependents.
- ``INCONCLUSIVE`` : phase failed (status==FAILED) or ran with an
                     unknown shape. Take no automatic action.

The evaluation never mutates the plan. The caller decides what to do
with the recommendation (skip dependents, retry, log only).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from kryon.tools.autonomous.pentest_planner import PhaseStatus, PlanPhase


class PhaseVerdict(str, Enum):
    USEFUL = "useful"
    PARTIAL = "partial"
    BARREN = "barren"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class PhaseEvaluation:
    """Outcome of a single phase evaluation. Immutable — the planner
    reads this and decides how to react."""

    verdict: PhaseVerdict
    reasoning: str
    delta_findings: int
    delta_critical_high: int
    expected_sigs_hit: tuple[str, ...] = field(default_factory=tuple)
    expected_sigs_missed: tuple[str, ...] = field(default_factory=tuple)
    recommend_retry: bool = False
    skip_dependents: bool = False
    quality_score: float = 0.0


# Per-phase signatures the evaluator expects to see in findings.
# A signature matches if it appears (case-insensitive) as either:
#   - prefix of finding.rule_id, OR
#   - substring of any textual field (title/description/evidence/message)
# Empty tuple => phase has no expected signatures (e.g. reporting) and
# completion alone is treated as success.
_PHASE_EXPECTED_SIGNATURES: dict[str, tuple[str, ...]] = {
    "recon": ("port", "service", "banner"),
    "vuln_scan": ("CVE-", "RCE", "XSS", "SQLi", "SSRF", "PVE-", "FGT-", "UNF-"),
    "proxmox_audit": ("PVE-",),
    "fortigate_audit": ("FGT-",),
    "unifi_audit": ("UNF-",),
    "ad_recon": ("ldap", "kerberos", "smb", "active directory", "port 389", "port 445", "port 88"),
    "exploitation": ("exploit", "rce", "shell", "session"),
    "post_exploit": ("credential", "persistence", "lateral", "hash", "ticket"),
    "api_fuzzing": ("API-", "OPENAPI", "BOLA", "GraphQL"),
    "reporting": (),  # success on completion regardless of evidence
}


# Phases whose failure should cascade — if these go BARREN, dependent
# phases will not produce useful results either, so skip them.
_GATING_PHASES = frozenset({"recon", "vuln_scan", "exploitation"})


def cascade_skip_dependents(plan: Any, gating_phase_name: str) -> int:
    """Mark every PENDING phase that depends on ``gating_phase_name``
    as SKIPPED. Returns the number of phases that were cascaded.

    Caller invokes this when an evaluation returns ``skip_dependents=True``
    so downstream phases gated by an unproductive predecessor don't waste
    budget. The plan is mutated in place.
    """
    cascaded = 0
    for p in plan.phases:
        if p.status == PhaseStatus.PENDING and gating_phase_name in p.depends_on:
            p.status = PhaseStatus.SKIPPED
            cascaded += 1
    return cascaded


def cascade_skip_remaining(plan: Any, except_names: tuple[str, ...] = ("reporting",)) -> int:
    """Mark every PENDING phase as SKIPPED, except those whose name is in
    ``except_names``. Returns the number of phases that were skipped.

    Used by F118 early termination: when the goal is satisfied we want to
    stop the LLM-driven phases (recon/vuln_scan/exploitation/...) but still
    let ``reporting`` run so the operator gets a written summary. The plan
    is mutated in place.
    """
    skipped = 0
    for p in plan.phases:
        if p.status == PhaseStatus.PENDING and p.name not in except_names:
            p.status = PhaseStatus.SKIPPED
            skipped += 1
    return skipped


def dedup_findings_by_rule_and_host(existing: list[Any], candidates: list[Any]) -> list[Any]:
    """Return items from ``candidates`` whose ``(rule_id, host)`` pair is
    not already present in ``existing``. Preserves input order. Used after
    parsing LLM-emitted findings to avoid the retry-doubles-findings bug
    where the same finding gets re-emitted on a retry pass.
    """
    seen: set[tuple[str, str]] = set()
    for f in existing:
        seen.add((str(getattr(f, "rule_id", "")), str(getattr(f, "host", ""))))
    kept: list[Any] = []
    for f in candidates:
        key = (str(getattr(f, "rule_id", "")), str(getattr(f, "host", "")))
        if key in seen:
            continue
        seen.add(key)
        kept.append(f)
    return kept


def _severity_lower(finding: Any) -> str:
    sev = getattr(finding, "severity", None)
    if sev is None:
        return ""
    return str(getattr(sev, "value", sev)).lower()


def _finding_text(finding: Any) -> str:
    """Return a lowercase blob with every text field we know about.
    Supports both the engage.Finding shape and the enterprise/findings
    shape used by ``tools.autonomous`` modules."""
    parts: list[str] = []
    for attr in ("rule_id", "title", "description", "evidence", "message", "host", "affected_asset"):
        val = getattr(finding, attr, "")
        if val:
            parts.append(str(val))
    return " ".join(parts).lower()


def _match_signature(finding: Any, sig: str) -> bool:
    """A signature matches if it appears as a rule_id prefix or as a
    substring in any text field. All comparisons case-insensitive."""
    sig_lower = sig.lower()
    rule_id = str(getattr(finding, "rule_id", "")).lower()
    if rule_id.startswith(sig_lower):
        return True
    return sig_lower in _finding_text(finding)


def _split_signatures(findings: list[Any], expected: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (hits, misses) preserving original casing of ``expected``."""
    hits: list[str] = []
    misses: list[str] = []
    for sig in expected:
        if any(_match_signature(f, sig) for f in findings):
            hits.append(sig)
        else:
            misses.append(sig)
    return tuple(hits), tuple(misses)


def _count_critical_high(findings: list[Any]) -> int:
    severe = {"critical", "high"}
    return sum(1 for f in findings if _severity_lower(f) in severe)


def evaluate_phase(
    phase: PlanPhase,
    findings_before: list[Any],
    findings_after: list[Any],
    *,
    expected_sigs: tuple[str, ...] | None = None,
) -> PhaseEvaluation:
    """Score a single phase based on what it produced.

    Args:
        phase: the plan phase that just finished.
        findings_before: snapshot of findings BEFORE the phase ran.
        findings_after:  full findings list AFTER the phase ran.
        expected_sigs:   override the per-phase default expected
                         signature tuple. Pass ``()`` to skip signature
                         matching entirely.
    """
    # Failed phases: no automatic action — caller logs and moves on.
    if phase.status == PhaseStatus.FAILED:
        return PhaseEvaluation(
            verdict=PhaseVerdict.INCONCLUSIVE,
            reasoning=f"phase '{phase.name}' status=FAILED",
            delta_findings=0,
            delta_critical_high=0,
        )

    delta_findings = max(0, len(findings_after) - len(findings_before))
    new_findings = findings_after[len(findings_before) :] if delta_findings > 0 else []
    delta_critical_high = _count_critical_high(new_findings)

    sigs = expected_sigs if expected_sigs is not None else _PHASE_EXPECTED_SIGNATURES.get(phase.name, ())
    hits, misses = _split_signatures(new_findings, sigs) if sigs else ((), ())

    # Reporting phase (or any phase with no expected sigs) — success on completion.
    if not sigs:
        return PhaseEvaluation(
            verdict=PhaseVerdict.USEFUL,
            reasoning=f"phase '{phase.name}' has no expected signatures; completion is success",
            delta_findings=delta_findings,
            delta_critical_high=delta_critical_high,
            expected_sigs_hit=(),
            expected_sigs_missed=(),
            quality_score=1.0,
        )

    # USEFUL: critical/high severity OR at least one expected signature hit.
    if delta_critical_high >= 1:
        return PhaseEvaluation(
            verdict=PhaseVerdict.USEFUL,
            reasoning=f"{delta_critical_high} critical/high findings",
            delta_findings=delta_findings,
            delta_critical_high=delta_critical_high,
            expected_sigs_hit=hits,
            expected_sigs_missed=misses,
            quality_score=1.0 if not misses else 0.85,
        )

    if hits:
        # Hit at least one expected signature but no critical/high — still useful.
        return PhaseEvaluation(
            verdict=PhaseVerdict.USEFUL,
            reasoning=f"hit expected signatures: {', '.join(hits)}",
            delta_findings=delta_findings,
            delta_critical_high=delta_critical_high,
            expected_sigs_hit=hits,
            expected_sigs_missed=misses,
            quality_score=0.75 if misses else 0.9,
        )

    # PARTIAL: got findings but didn't match any expected signature.
    if delta_findings > 0:
        return PhaseEvaluation(
            verdict=PhaseVerdict.PARTIAL,
            reasoning=f"{delta_findings} new findings but none matched expected signatures {list(sigs)}",
            delta_findings=delta_findings,
            delta_critical_high=0,
            expected_sigs_hit=(),
            expected_sigs_missed=misses,
            recommend_retry=True,
            quality_score=0.4,
        )

    # BARREN: zero new findings AND zero signature hits.
    is_gating = phase.name in _GATING_PHASES
    return PhaseEvaluation(
        verdict=PhaseVerdict.BARREN,
        reasoning=f"phase '{phase.name}' produced no new evidence",
        delta_findings=0,
        delta_critical_high=0,
        expected_sigs_hit=(),
        expected_sigs_missed=misses,
        skip_dependents=is_gating,
        quality_score=0.0,
    )
