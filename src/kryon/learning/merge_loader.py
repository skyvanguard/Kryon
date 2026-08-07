"""F77.G.6 — Load existing auto-skills for the merge decider.

The decider needs a list of `ExistingSkill` representing every skill
that came out of the auto loop and could collide with a fresh
cluster. Hand-written core playbooks (`pentest`, `recon-scout`, etc.)
are NOT included — they were curated by a human and their priority
keeps them in front of any auto-skill regardless. The decider only
gates the *auto* side from polluting itself.

Scan locations (in this exact order so a draft promoted to playbooks
wins precedence over a stale draft of the same name):

  1. `<KRYON_HOME>/.../playbooks/_drafts/` if the operator's path
     resolves there (older convention; gracefully no-op if absent).
  2. `<drafts_dir>/_auto/`               — auto-pipeline pass.
  3. `<drafts_dir>/_rejected/`           — auto-pipeline fail.
  4. `<drafts_dir>/`                     — operator-edited drafts.

Each `.md` is parsed for its YAML frontmatter. The decider only needs:
  - name (from frontmatter or filename stem)
  - version (parsed from .vN suffix or defaults to 1)
  - representative_chain (from `_provenance.representative_chain`)
  - tech (from `_provenance.representative_tech` or `triggers.tech`)

Drafts without a `_provenance` block are silently skipped — those are
likely hand-edited drafts the operator has full control over; the
decider should not second-guess them.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml

from kryon.learning.draft_writer import get_drafts_dir
from kryon.learning.merge_decider import ExistingSkill

logger = logging.getLogger(__name__)

__all__ = ["load_existing_for_merge", "parse_skill_signature"]

# Filenames like "pci-dss-audit.v3" → base "pci-dss-audit", version 3.
_VERSION_RE = re.compile(r"^(?P<base>.+?)\.v(?P<n>\d+)$")


def _split_name_and_version(stem: str) -> tuple[str, int]:
    """Filename stem → (base_name, version). Versionless names → (stem, 1)."""
    m = _VERSION_RE.match(stem)
    if not m:
        return stem, 1
    return m.group("base"), int(m.group("n"))


def _parse_frontmatter(text: str) -> dict[str, Any] | None:
    """Extract the YAML frontmatter from a `---\n...\n---\nbody` doc.

    Returns None when the file has no frontmatter — the caller skips
    those drafts (we won't second-guess a hand-edited skill that
    decided to omit the YAML header)."""
    if not text.startswith("---"):
        return None
    # Slice after the first --- newline to the next --- on its own line.
    parts = text.split("\n---", 2)
    if len(parts) < 2:
        return None
    yaml_text = parts[0][3:]  # strip leading '---'
    try:
        loaded = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        return None
    return loaded if isinstance(loaded, dict) else None


def parse_skill_signature(md_path: Path) -> ExistingSkill | None:
    """Read one .md file, extract the merge signature.

    Returns None when:
      - the file has no parseable frontmatter, OR
      - the frontmatter has no `_provenance.representative_chain`
        (i.e. the draft predates F77.G.6 or was hand-written)

    Hand-written drafts are not skipped maliciously — they're just not
    candidates for *automatic* merge. The operator can still promote
    them; the decider just doesn't see them as collision targets.
    """
    try:
        text = md_path.read_text(encoding="utf-8")
    except OSError as e:
        logger.debug("merge_loader: cannot read %s: %s", md_path, e)
        return None

    fm = _parse_frontmatter(text)
    if not fm:
        return None

    provenance = fm.get("_provenance") or {}
    chain = provenance.get("representative_chain")
    if not isinstance(chain, list) or not chain:
        return None

    tech_raw = provenance.get("representative_tech")
    if not isinstance(tech_raw, list):
        # Fall back to triggers.tech, which is always present.
        triggers = fm.get("triggers") or {}
        tech_raw = triggers.get("tech") if isinstance(triggers, dict) else []
    tech = tuple(str(t) for t in (tech_raw or []))

    name_from_fm = fm.get("name")
    raw_stem = name_from_fm if isinstance(name_from_fm, str) else md_path.stem
    base, version = _split_name_and_version(raw_stem)

    return ExistingSkill(
        name=base,
        version=version,
        representative_chain=tuple(str(s) for s in chain),
        tech=tech,
    )


def _candidate_dirs(drafts_root: Path) -> list[Path]:
    """In-order list of directories to scan. Missing dirs are filtered."""
    candidates = [
        drafts_root / "_auto",
        drafts_root / "_rejected",
        drafts_root,
    ]
    return [d for d in candidates if d.is_dir()]


def load_existing_for_merge(drafts_root: Path | None = None) -> list[ExistingSkill]:
    """Scan the drafts directories and build the ExistingSkill list.

    De-duplicates by base name: if the same base appears in multiple
    locations (e.g. `_auto/pci-dss-audit.md` AND
    `~/.kryon/drafts/pci-dss-audit.md`), the highest version wins;
    same version → first scanned wins.

    Returns an empty list when no drafts directory exists yet (fresh
    install) — the decider then short-circuits to ADD for every
    cluster, which is the correct cold-start behaviour."""
    root = drafts_root if drafts_root is not None else get_drafts_dir()
    if not root.is_dir():
        return []

    by_base: dict[str, ExistingSkill] = {}
    for d in _candidate_dirs(root):
        for path in sorted(d.glob("*.md")):
            sig = parse_skill_signature(path)
            if sig is None:
                continue
            existing = by_base.get(sig.name)
            if existing is None or sig.version > existing.version:
                by_base[sig.name] = sig
    return list(by_base.values())
