"""F147 — Skill auto-update from a remote playbooks repo.

Pulls a git repo of community / vendor playbooks, validates each
markdown file's frontmatter against the SkillLoader schema, and
copies the valid ones into the local ``playbooks/`` directory. Never
overwrites an existing local skill unless ``--force`` is passed.

This is the "long-term sustenance" lever for Kryon: as new threats
emerge (a new CVE, a new compliance framework, a new vendor's API),
operators publish a playbook upstream once and every Kryon instance
can pull it in with a single command.

Pure subprocess for the git clone — no GitPython dep. Validation
uses the existing ``SkillLoader`` parser so any drift between the
repo's schema and Kryon's surfaces as a clear error, not a silent
broken skill.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class UpdateResult:
    """Outcome of one update pass."""

    added: list[str] = field(default_factory=list)  # new skill files copied in
    updated: list[str] = field(default_factory=list)  # existing skills overwritten (force only)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (name, reason)
    failed: list[tuple[str, str]] = field(default_factory=list)  # (name, error)

    @property
    def total_added(self) -> int:
        return len(self.added) + len(self.updated)


def _git_clone(repo_url: str, dest: Path, branch: str = "main") -> tuple[bool, str]:
    """Shallow-clone ``repo_url`` into ``dest``. Returns
    ``(ok, error_msg)``."""
    cmd = ["git", "clone", "--depth", "1", "--branch", branch, repo_url, str(dest)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout or "git clone failed").strip()
        return True, ""
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, str(exc)


def _validate_skill(path: Path) -> tuple[bool, str]:
    """Validate frontmatter with SkillLoader. Returns ``(ok, error)``."""
    try:
        from kryon.skills.loader import _FRONTMATTER_RE, SkillLoader

        text = path.read_text(encoding="utf-8")
        m = _FRONTMATTER_RE.match(text)
        if not m:
            return False, "missing YAML frontmatter"
        # Defer full schema validation to SkillLoader's parser by
        # scanning the parent directory and checking we got a hit.
        loader = SkillLoader(skill_dirs=[path.parent])
        skills = loader.scan()
        match = next((s for s in skills if s.name and path.stem == s.name), None)
        if match is None:
            return False, "could not parse as a valid Skill (unknown frontmatter shape)"
        return True, ""
    except (OSError, ImportError) as exc:
        return False, str(exc)


def update_from_git(
    repo_url: str,
    *,
    branch: str = "main",
    playbooks_subdir: str = "playbooks",
    local_playbooks_dir: Path | None = None,
    force: bool = False,
) -> UpdateResult:
    """Clone ``repo_url`` and merge its playbooks into the local tree.

    Args:
        repo_url:            HTTPS or SSH git URL.
        branch:              branch to checkout (default ``main``).
        playbooks_subdir:    where playbooks live inside the repo.
        local_playbooks_dir: target directory (defaults to the kryon
                             source tree's playbooks/).
        force:               overwrite existing playbooks with the
                             upstream version (default False — keep
                             local changes safe).
    """
    result = UpdateResult()
    target = local_playbooks_dir or (Path(__file__).resolve().parent / "playbooks")
    target.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="kryon-skills-update-") as tmp:
        clone_dir = Path(tmp) / "repo"
        ok, err = _git_clone(repo_url, clone_dir, branch=branch)
        if not ok:
            result.failed.append(("__clone__", err))
            return result

        src_root = clone_dir / playbooks_subdir
        if not src_root.exists():
            result.failed.append(("__subdir__", f"missing {playbooks_subdir} in repo"))
            return result

        for md in sorted(src_root.rglob("*.md")):
            rel = md.relative_to(src_root)
            dest = target / rel
            stem = md.stem
            valid, verr = _validate_skill(md)
            if not valid:
                result.failed.append((str(rel), verr))
                continue
            if dest.exists() and not force:
                result.skipped.append((str(rel), "already exists locally; pass force=True to overwrite"))
                continue
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                if dest.exists():
                    shutil.copy2(md, dest)
                    result.updated.append(str(rel))
                else:
                    shutil.copy2(md, dest)
                    result.added.append(str(rel))
            except OSError as exc:
                result.failed.append((str(rel), str(exc)))
                continue

    return result
