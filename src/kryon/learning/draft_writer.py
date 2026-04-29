"""Filesystem IO for synthesized skill drafts.

Drafts live in `~/.kryon/drafts/` (override via `KRYON_DRAFTS_DIR`) so
they stay outside the project's `playbooks/` until the operator
explicitly promotes one via `/skill promote <name>`.

This split is intentional:
  * Auto-synthesis can run on every engagement without ever touching
    the version-controlled skill catalog.
  * The operator reviews + edits drafts at their own pace.
  * If they discard, no commit ever happened.

For tests we override the env var to a tmp path. For production the
default (`~/.kryon/drafts/`) is created on first write.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from kryon.learning.skill_synthesizer import SkillDraft, synthesize_draft

logger = logging.getLogger(__name__)


_DRAFTS_ENV = "KRYON_DRAFTS_DIR"


def get_drafts_dir() -> Path:
    """Resolve the drafts directory honouring KRYON_DRAFTS_DIR override."""
    raw = os.environ.get(_DRAFTS_ENV)
    if raw:
        return Path(raw)
    return Path.home() / ".kryon" / "drafts"


def list_existing_names() -> set[str]:
    """Return the set of draft names currently on disk (no .md suffix)."""
    d = get_drafts_dir()
    if not d.is_dir():
        return set()
    return {p.stem for p in d.glob("*.md")}


def write_draft(draft: SkillDraft) -> Path:
    """Persist a draft to `<drafts_dir>/<name>.md`. Creates the dir if missing.

    Overwrites if a file with the same name already exists — the synthesizer's
    counter normally prevents this, but a hand-edited draft will be replaced.
    """
    d = get_drafts_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{draft.name}.md"
    path.write_text(draft.to_markdown(), encoding="utf-8")
    logger.info("draft persisted: %s", path)
    return path


def read_draft(name: str) -> str | None:
    """Return the raw markdown for one draft, or None if absent."""
    path = get_drafts_dir() / f"{name}.md"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def delete_draft(name: str) -> bool:
    """Remove one draft from disk. Returns True if it existed."""
    path = get_drafts_dir() / f"{name}.md"
    if not path.is_file():
        return False
    path.unlink()
    logger.info("draft deleted: %s", path)
    return True


def try_synthesize_and_persist(
    experience: dict[str, Any],
    *,
    min_outcome: str = "partial",
) -> Path | None:
    """High-level helper: synthesize one experience and persist if eligible.

    Returns the path of the written draft, or None if the experience didn't
    qualify (low outcome / thin chain).

    This is the function `auto_extract` calls after persisting an experience —
    it composes synthesize_draft + write_draft + collision-avoidance via
    `existing_names`.
    """
    draft = synthesize_draft(
        experience,
        min_outcome=min_outcome,
        existing_names=list_existing_names(),
    )
    if draft is None:
        return None
    return write_draft(draft)
