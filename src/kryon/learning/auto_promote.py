"""F138 — Auto-promote skill drafts to playbooks.

Closes the learning loop end-to-end. Today F1 writes drafts to
``~/.kryon/drafts/`` after each successful engagement, F2 scores
them via Wilson lower-bound + reusability (cross-engagement
selections), and F3 has an evaluator gate. But the operator still
has to run ``/skill promote`` manually.

This module promotes the drafts that pass a configurable bar:

  - Wilson lower-bound (95% CI) >= 0.7 (default; env-tunable).
  - Reusability score >= 3 (default; env-tunable). Means the draft
    was selected by the loader in at least 3 distinct engagements.
  - F3 evaluator gate passed (when the evaluator can be loaded).

Promotion = move the ``.md`` file from ``~/.kryon/drafts/`` to
``src/kryon/skills/playbooks/`` and emit an audit-log entry.

**Banking-safe defaults**: ``KRYON_AUTO_PROMOTE_SKILLS=true`` is the
opt-in flag. Off by default — an unattended Kryon should NOT
silently grow its playbook surface in a regulated environment
without operator review.

Pure-ish module: file I/O happens in ``promote_draft`` but is wrapped
so failures don't abort the engagement. Scores are passed in (caller
queries skill_scorer + selection_telemetry).
"""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PromotionDecision:
    """Outcome of evaluating a single draft."""

    draft_name: str
    promote: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)
    wilson_lower_bound: float = 0.0
    reusability_score: int = 0


@dataclass
class PromotionResult:
    """Outcome of the auto-promote pass."""

    promoted: list[str] = field(default_factory=list)
    skipped: list[PromotionDecision] = field(default_factory=list)
    errored: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total_promoted(self) -> int:
        return len(self.promoted)


def _env_true(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _wilson_threshold() -> float:
    try:
        return float(os.environ.get("KRYON_AUTO_PROMOTE_WILSON_MIN", "0.7"))
    except ValueError:
        return 0.7


def _reusability_threshold() -> int:
    try:
        return int(os.environ.get("KRYON_AUTO_PROMOTE_REUSABILITY_MIN", "3"))
    except ValueError:
        return 3


def evaluate_draft(
    *,
    draft_name: str,
    wilson_lower_bound: float,
    reusability_score: int,
    evaluator_passed: bool = True,
) -> PromotionDecision:
    """Pure decision: does this draft pass the promotion bar?

    Args:
        draft_name:           filename stem (e.g. ``recon-deep``).
        wilson_lower_bound:   skill_scorer score in [0,1].
        reusability_score:    distinct-engagement selection count.
        evaluator_passed:     F3 evaluator gate (default True so callers
                              that don't have an evaluator wired up
                              don't get falsely blocked).
    """
    wilson_min = _wilson_threshold()
    reuse_min = _reusability_threshold()

    reasons: list[str] = []
    if wilson_lower_bound < wilson_min:
        reasons.append(f"Wilson LB {wilson_lower_bound:.2f} < {wilson_min:.2f}")
    if reusability_score < reuse_min:
        reasons.append(f"reusability {reusability_score} < {reuse_min}")
    if not evaluator_passed:
        reasons.append("F3 evaluator gate failed")

    promote = not reasons
    if promote:
        reasons = ("all thresholds met",)
    return PromotionDecision(
        draft_name=draft_name,
        promote=promote,
        reasons=tuple(reasons),
        wilson_lower_bound=wilson_lower_bound,
        reusability_score=reusability_score,
    )


def promote_draft(
    *,
    draft_path: Path,
    playbooks_dir: Path,
) -> tuple[bool, str]:
    """Move the draft markdown into ``playbooks_dir``. Returns
    ``(ok, error_or_destination_path)``."""
    if not draft_path.exists():
        return False, f"draft missing: {draft_path}"
    dest = playbooks_dir / draft_path.name
    if dest.exists():
        return False, f"target exists, refusing to overwrite: {dest}"
    try:
        playbooks_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(draft_path), str(dest))
        return True, str(dest)
    except OSError as exc:
        return False, str(exc)


def auto_promote_drafts(
    *,
    drafts_dir: Path,
    playbooks_dir: Path,
    score_lookup,  # Callable[[str], tuple[float, int, bool]]
    enabled: bool | None = None,
) -> PromotionResult:
    """Walk ``drafts_dir``, decide each, and promote those that pass.

    Args:
        drafts_dir:    directory containing draft ``.md`` files.
        playbooks_dir: target directory for promoted playbooks.
        score_lookup:  callable that takes a draft name (stem) and
                       returns ``(wilson_lb, reusability, evaluator_passed)``.
                       Caller wires this to skill_scorer +
                       selection_telemetry + skill_evaluator.
        enabled:       override the ``KRYON_AUTO_PROMOTE_SKILLS`` env
                       gate (mainly for tests). ``None`` consults env.
    """
    result = PromotionResult()
    if enabled is None:
        enabled = _env_true("KRYON_AUTO_PROMOTE_SKILLS")
    if not enabled:
        logger.info("auto-promote disabled (KRYON_AUTO_PROMOTE_SKILLS != true)")
        return result
    if not drafts_dir.exists():
        return result

    for draft_path in sorted(drafts_dir.glob("*.md")):
        stem = draft_path.stem
        try:
            wilson, reuse, evaluator_ok = score_lookup(stem)
        except Exception as exc:  # pragma: no cover
            result.errored.append((stem, f"score lookup failed: {exc}"))
            continue
        decision = evaluate_draft(
            draft_name=stem,
            wilson_lower_bound=float(wilson),
            reusability_score=int(reuse),
            evaluator_passed=bool(evaluator_ok),
        )
        if not decision.promote:
            result.skipped.append(decision)
            continue
        ok, info = promote_draft(draft_path=draft_path, playbooks_dir=playbooks_dir)
        if ok:
            result.promoted.append(info)
        else:
            result.errored.append((stem, info))
    return result
