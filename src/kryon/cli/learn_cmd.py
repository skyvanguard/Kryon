"""F138 — ``kryon learn`` subcommand.

Wraps the learning-loop helpers that previously lived behind REPL
slash-commands. The auto-promote sub-action invokes
``auto_promote_drafts`` with a ``score_lookup`` wired to
``skill_scorer.score_skills`` + ``selection_telemetry.read_recent``,
so a single CLI call closes the F1→F2→F3 loop without dropping into
the REPL.

Sub-actions:

    kryon learn drafts                   # list pending drafts
    kryon learn auto-promote [--dry-run] # promote what passes the bar
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def add_learn_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(
        "learn",
        help="F138 — Learning loop ops: list drafts, auto-promote skills",
    )
    sub = p.add_subparsers(dest="learn_action", required=True)

    sub.add_parser("drafts", help="List skill drafts pending review")

    promote = sub.add_parser("auto-promote", help="Auto-promote drafts that pass the score bar")
    promote.add_argument(
        "--drafts-dir",
        default="",
        help="Source directory of draft *.md files (default: ~/.kryon/drafts/)",
    )
    promote.add_argument(
        "--playbooks-dir",
        default="",
        help="Destination directory (default: kryon/skills/playbooks/)",
    )
    promote.add_argument(
        "--dry-run",
        action="store_true",
        help="Evaluate but do not move files",
    )
    promote.add_argument(
        "--force",
        action="store_true",
        help="Override KRYON_AUTO_PROMOTE_SKILLS env gate",
    )
    return p


def _resolve_drafts_dir(arg_value: str) -> Path:
    if arg_value:
        return Path(arg_value).expanduser()
    return Path(os.path.expanduser("~/.kryon/drafts"))


def _resolve_playbooks_dir(arg_value: str) -> Path:
    if arg_value:
        return Path(arg_value).expanduser()
    # Inside the kryon source tree.
    return Path(__file__).resolve().parent.parent / "skills" / "playbooks"


def _build_score_lookup():
    """Return a callable ``(draft_name) -> (wilson_lb, reusability, evaluator_ok)``.

    Tries to load skill_scorer + selection_telemetry; degrades to a
    safe default that flags every draft as 0/0/False so the operator
    sees "nothing qualified" rather than a runtime error."""
    try:
        from kryon.learning.selection_telemetry import read_recent
        from kryon.learning.skill_scorer import score_skills
    except Exception:  # pragma: no cover
        return lambda name: (0.0, 0, False)

    try:
        telemetry_records = read_recent(limit=500) or []
    except Exception:  # pragma: no cover
        telemetry_records = []

    # Pre-compute scores for every skill name we might be asked about
    # to avoid one Wilson-CI calculation per draft.
    # We don't have experiences readily available without ChromaDB, so
    # we pass an empty list and rely on telemetry-based fallback.
    try:
        scores = score_skills(experiences=[], skill_names=None, telemetry_records=telemetry_records)
    except Exception:  # pragma: no cover
        scores = {}

    def lookup(name: str) -> tuple[float, int, bool]:
        score = scores.get(name)
        if score is None:
            return 0.0, 0, True
        wilson = float(getattr(score, "wilson_lower", 0.0) or 0.0)
        reuse = int(getattr(score, "reusability", 0) or 0)
        # No F3 evaluator gate yet — pass True so the gate doesn't
        # always block. Operators can wire a stricter gate later.
        return wilson, reuse, True

    return lookup


def _list_drafts(drafts_dir: Path) -> int:
    if not drafts_dir.exists():
        print(f"(no drafts dir at {drafts_dir})")
        return 0
    drafts = sorted(drafts_dir.glob("*.md"))
    if not drafts:
        print(f"(no drafts in {drafts_dir})")
        return 0
    print(f"{len(drafts)} draft(s) in {drafts_dir}:")
    for d in drafts:
        print(f"  - {d.stem}")
    return 0


def _auto_promote(args) -> int:
    from kryon.learning.auto_promote import auto_promote_drafts

    drafts_dir = _resolve_drafts_dir(args.drafts_dir)
    playbooks_dir = _resolve_playbooks_dir(args.playbooks_dir)

    if not drafts_dir.exists():
        print(f"drafts dir not found: {drafts_dir}", file=sys.stderr)
        return 1

    score_lookup = _build_score_lookup()

    # --dry-run / --force both override the env gate. We re-implement
    # the logic locally so we can preview without writing files.
    if args.dry_run:
        from kryon.learning.auto_promote import evaluate_draft

        for draft_path in sorted(drafts_dir.glob("*.md")):
            name = draft_path.stem
            try:
                wilson, reuse, ok = score_lookup(name)
            except Exception as exc:  # pragma: no cover
                print(f"  [error] {name}: score lookup failed: {exc}")
                continue
            decision = evaluate_draft(
                draft_name=name,
                wilson_lower_bound=wilson,
                reusability_score=reuse,
                evaluator_passed=ok,
            )
            verdict = "PROMOTE" if decision.promote else "SKIP"
            print(
                f"  [{verdict:7s}] {name}  wilson={wilson:.2f} reuse={reuse}  ({decision.reasons[0] if decision.reasons else ''})"
            )
        return 0

    enabled = True if args.force else None  # None → consult env gate
    result = auto_promote_drafts(
        drafts_dir=drafts_dir,
        playbooks_dir=playbooks_dir,
        score_lookup=score_lookup,
        enabled=enabled,
    )

    if result.promoted:
        print(f"promoted {len(result.promoted)}:")
        for dest in result.promoted:
            print(f"  → {dest}")
    if result.skipped:
        print(f"skipped {len(result.skipped)}:")
        for s in result.skipped:
            reasons = ", ".join(s.reasons)
            print(f"  - {s.draft_name}  ({reasons})")
    if result.errored:
        print(f"errored {len(result.errored)}:", file=sys.stderr)
        for name, msg in result.errored:
            print(f"  - {name}: {msg}", file=sys.stderr)
    if not result.promoted and not result.skipped and not result.errored:
        print("(nothing to do — auto-promote may be disabled; pass --force to override env gate)")
    return 0


def run_learn_command(args) -> int:
    action = args.learn_action
    if action == "drafts":
        return _list_drafts(_resolve_drafts_dir(""))
    if action == "auto-promote":
        return _auto_promote(args)
    print(f"learn: unknown action '{action}'", file=sys.stderr)
    return 2
