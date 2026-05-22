"""Auto-skill pipeline — orchestrate detection → synth → eval → write.

Glue between `pattern_detector`, `skill_synthesizer.synthesize_from_cluster`,
`skill_evaluator`, and `draft_writer`. Every external dependency is
injectable so callers can plug:
  * `experience_loader=lambda: list_experiences()` (or a stub in tests)
  * `findings_loader=lambda: list_findings()` (or a stub)
  * `llm_caller=lambda prompt: ollama_chat(prompt)` (or None)

Output layout under `<drafts_dir>/`:
  _auto/<name>.md            — eval passed; ready for human review
  _auto/<name>.eval.json     — eval report sidecar
  _rejected/<name>.md        — eval rejected or skipped
  _rejected/<name>.eval.json — eval report sidecar (always)

The split lets the operator tell at a glance which drafts were
auto-validated vs which still need a manual look. Both directories
live under `KRYON_DRAFTS_DIR` and are git-ignored by default — no
auto-skill ever writes inside `playbooks/` without human action.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from kryon.learning.draft_writer import get_drafts_dir, list_existing_names
from kryon.learning.merge_decider import MergeDecision, decide_merge_action
from kryon.learning.merge_loader import load_existing_for_merge
from kryon.learning.pattern_detector import (
    ChainCluster,
    detect_recurrent_chains,
)
# F203.S — Guide score (relevance + naturalness) as second-axis filter
# post-CWE-eval. Detects placeholder soup, repeated lines, frontmatter/body
# mismatches that the technical eval can miss.
from kryon.learning.guide_scorer import (
    GUIDE_DEFAULT_THRESHOLD,
    score_draft,
)
from kryon.learning.skill_evaluator import (
    EvalReport,
    evaluate_draft_against_corpus,
)
from kryon.learning.skill_synthesizer import (
    SkillDraft,
    synthesize_from_cluster,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PipelineResult:
    clusters_detected: int = 0
    drafts_synthesized: int = 0
    drafts_passed: int = 0
    drafts_rejected: int = 0
    drafts_skipped: int = 0
    # F77.G.6 — merge-ternary outcome counts. drafts_discarded covers
    # both quality-floor and ambiguous-band discards.
    clusters_added: int = 0
    clusters_merged: int = 0
    clusters_discarded: int = 0
    output_paths: tuple[str, ...] = field(default_factory=tuple)


def _safe_call(fn: Callable[[], list] | None, label: str) -> list:
    """Invoke a loader, swallow + log on failure (return [])."""
    if fn is None:
        return []
    try:
        return fn() or []
    except Exception as e:  # noqa: BLE001
        logger.warning("auto_pipeline: %s loader failed: %s", label, e)
        return []


def _existing_names_across_subdirs(drafts_root: Path) -> set[str]:
    """Names that already live in any of _auto/ / _rejected/ / root."""
    names: set[str] = set(list_existing_names())
    for sub in ("_auto", "_rejected"):
        d = drafts_root / sub
        if d.is_dir():
            for p in d.glob("*.md"):
                names.add(p.stem)
    return names


def _write_outputs(
    draft: SkillDraft,
    report: EvalReport,
    drafts_root: Path,
) -> tuple[Path, Path]:
    """Write the draft .md + eval.json sidecar in the appropriate subdir.

    Returns (md_path, json_path).
    """
    subdir_name = "_auto" if report.eval_status == "passed" else "_rejected"
    subdir = drafts_root / subdir_name
    subdir.mkdir(parents=True, exist_ok=True)

    md_path = subdir / f"{draft.name}.md"
    json_path = subdir / f"{draft.name}.eval.json"

    md_path.write_text(draft.to_markdown(), encoding="utf-8")

    # F203.S — enrich the eval sidecar with the Guide score (relevance +
    # naturalness). Second-axis filter for textual quality issues (placeholder
    # soup, dup lines, frontmatter/body mismatch) that the technical CWE eval
    # gate can miss. Pure analytic, no LLM calls.
    eval_payload = asdict(report)
    try:
        guide = score_draft(draft)
        eval_payload["guide_score"] = {
            "relevance": round(guide.relevance, 3),
            "naturalness": round(guide.naturalness, 3),
            "combined": round(guide.combined, 3),
            "threshold": GUIDE_DEFAULT_THRESHOLD,
            "passed_guide": guide.combined >= GUIDE_DEFAULT_THRESHOLD,
            "reasons": list(guide.reasons),
        }
    except Exception as e:  # noqa: BLE001 — guide_scorer must never block writes
        eval_payload["guide_score"] = {"error": str(e)}

    json_path.write_text(
        json.dumps(eval_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return md_path, json_path


def run_auto_pipeline(
    *,
    experience_loader: Callable[[], list[dict]] | None = None,
    findings_loader: Callable[[], list[dict]] | None = None,
    llm_caller: Callable[[str], str] | None = None,
    min_repetitions: int = 3,
    similarity_threshold: float = 0.75,
    min_pass_rate: float = 0.7,
    min_findings_evaluated: int = 3,
) -> PipelineResult:
    """Run the full auto-skill detection cycle.

    Returns a PipelineResult with counts and the paths written. Failures
    in either loader are swallowed (logged) — the pipeline never raises
    so it can be invoked from a `/skill auto detect` REPL command without
    risk of taking down the session.
    """
    experiences = _safe_call(experience_loader, "experience")
    findings = _safe_call(findings_loader, "findings")

    clusters: list[ChainCluster] = detect_recurrent_chains(
        experiences,
        min_repetitions=min_repetitions,
        similarity_threshold=similarity_threshold,
    )

    if not clusters:
        return PipelineResult()

    drafts_root = get_drafts_dir()
    existing = _existing_names_across_subdirs(drafts_root)

    # F77.G.6 — load existing auto-skill signatures for the merge
    # decider. Best-effort: if loading fails (corrupt frontmatter on
    # disk, etc.) we degrade to "no comparisons" which always returns
    # ADD — equivalent to the pre-F77.G.6 behaviour.
    try:
        existing_skills_for_merge = load_existing_for_merge(drafts_root)
    except Exception as e:  # noqa: BLE001
        logger.warning("auto_pipeline: merge-loader failed (%s); treating corpus as empty", e)
        existing_skills_for_merge = []

    paths: list[str] = []
    passed = rejected = skipped = synthesized = 0
    added = merged = discarded = 0
    for cluster in clusters:
        # F77.G.6 — triage BEFORE synthesis. Discarded clusters never
        # produce a draft on disk; merged clusters get versioned names
        # (.v2.md) so they don't shadow the existing skill.
        decision = decide_merge_action(cluster, existing_skills_for_merge)
        if decision.decision == "discard":
            discarded += 1
            logger.info(
                "auto_pipeline: discard cluster %s (%s)",
                cluster.cluster_id,
                decision.reason,
            )
            continue

        try:
            draft = synthesize_from_cluster(
                cluster,
                existing_names=existing,
                llm_caller=llm_caller,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "auto_pipeline: synth failed for cluster %s: %s",
                cluster.cluster_id,
                e,
            )
            continue
        synthesized += 1

        # When MERGE, rename the draft to the proposed .vN form so the
        # filename + frontmatter agree. The body stays the same; the
        # operator inspects the diff against v(N-1) before promoting.
        if decision.decision == "merge" and decision.target_draft_name:
            draft = _rename_draft_for_merge(draft, decision)
            merged += 1
        else:
            added += 1
        existing.add(draft.name)

        report = evaluate_draft_against_corpus(
            draft=draft,
            cluster=cluster,
            findings=findings,
            min_pass_rate=min_pass_rate,
            min_findings_evaluated=min_findings_evaluated,
        )

        try:
            md_path, json_path = _write_outputs(draft, report, drafts_root)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "auto_pipeline: write failed for %s: %s",
                draft.name,
                e,
            )
            continue
        paths.extend([str(md_path), str(json_path)])

        if report.eval_status == "passed":
            passed += 1
        elif report.eval_status == "rejected":
            rejected += 1
        else:  # skipped
            skipped += 1

    return PipelineResult(
        clusters_detected=len(clusters),
        drafts_synthesized=synthesized,
        drafts_passed=passed,
        drafts_rejected=rejected,
        drafts_skipped=skipped,
        clusters_added=added,
        clusters_merged=merged,
        clusters_discarded=discarded,
        output_paths=tuple(paths),
    )


def _rename_draft_for_merge(draft: SkillDraft, decision: MergeDecision) -> SkillDraft:
    """Replace the draft's name + the `name` key in the frontmatter
    with the merge-decider's proposed versioned slug. Body untouched.

    SkillDraft is frozen, so we build a fresh instance — never mutate
    in place."""
    new_name = decision.target_draft_name or draft.name
    new_frontmatter = dict(draft.frontmatter)
    new_frontmatter["name"] = new_name
    # Record the merge lineage on `_provenance` so the curator sees
    # which existing skill this was proposed to supersede.
    prov = dict(new_frontmatter.get("_provenance") or {})
    prov["merge_from"] = decision.target_existing_name
    prov["merge_from_version"] = (decision.target_new_version or 1) - 1
    prov["merge_similarity"] = decision.max_similarity
    new_frontmatter["_provenance"] = prov
    return SkillDraft(
        name=new_name,
        body=draft.body,
        frontmatter=new_frontmatter,
    )
