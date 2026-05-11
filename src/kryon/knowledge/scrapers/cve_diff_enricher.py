"""
CVE diff enricher — take normalized advisories from github_advisory_scraper
and fetch the actual before/after diff for each fix commit, producing
RAG-ready records.

For each (ghsa_id, fix_commit) we emit one record with:
  - the CVE/CWE context (from advisory)
  - the full unified diff
  - per-file: path, added/removed function calls (extracted by git_diff_fix)
  - a short textual 'pattern' — the top changed hunk, suitable for embedding

The enricher is intentionally lazy: it can process advisories one at a
time and skip repos it cannot reach. It produces a JSONL that
ChromaDB can ingest as-is.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from kryon.tools.code.git_tools import (
    _git_clone_and_index_impl,
    _git_diff_fix_impl,
)

logger = logging.getLogger(__name__)

# Budget knobs — tune for "big ingestion" vs "quick sample"
_DEFAULT_MAX_DIFF_CHARS = 8000
_DEFAULT_PER_COMMIT_FILES = 5
_SHARED_REPO_CACHE = Path(os.environ.get("KRYON_SOURCES_ROOT", "/workspace/sources"))


@dataclass
class EnrichedEntry:
    ghsa_id: str
    cve_id: str
    cwe_ids: list[str]
    summary: str
    severity: str
    ecosystem: str
    package: str
    commit_sha: str
    repo: str  # "owner/name"
    subject: str  # commit subject
    files: list[dict]  # from git_diff_fix.files
    pattern: str  # short text for embedding

    def to_dict(self) -> dict:
        return self.__dict__


def _ensure_repo_cloned(owner: str, repo: str) -> str | None:
    """Clone (or reuse) owner/repo; return local path or None on failure."""
    url = f"https://github.com/{owner}/{repo}.git"
    try:
        # git_clone_and_index already caches by URL hash
        raw = _git_clone_and_index_impl(url, shallow=False)
        idx = json.loads(raw)
        if "error" in idx:
            logger.warning("clone %s/%s failed: %s", owner, repo, idx["error"][:200])
            return None
        return idx.get("repo_path")
    except Exception as e:
        logger.warning("clone %s/%s raised: %s", owner, repo, e)
        return None


def _ensure_sha_available(repo_path: str, sha: str) -> bool:
    """Fetch the fix commit into the (shallow) clone if missing.

    Advisory-sourced SHAs often fall outside the last few commits of a
    shallow clone, so we fetch explicitly.
    """
    # Does the SHA already resolve?
    r = subprocess.run(
        ["git", "cat-file", "-e", sha],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode == 0:
        return True

    # Try fetching that specific object
    r = subprocess.run(
        ["git", "fetch", "--depth", "5", "origin", sha],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if r.returncode == 0:
        return True

    # Last resort — unshallow (expensive; only for critical enrichments)
    logger.debug("unshallowing %s to find %s", repo_path, sha[:10])
    r = subprocess.run(
        ["git", "fetch", "--unshallow"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if r.returncode != 0:
        return False

    r = subprocess.run(
        ["git", "cat-file", "-e", sha],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=False,
    )
    return r.returncode == 0


def _build_pattern_text(
    advisory: dict,
    diff_data: dict,
    max_chars: int = _DEFAULT_MAX_DIFF_CHARS,
) -> str:
    """Produce a compact, embedding-friendly pattern string.

    Layout (structural-first so code-aware embedders can exploit it):
      [summary]
      [CWE tag(s)]
      [commit subject]
      ---
      FILE: path
      CHANGED FUNCTIONS: f1, f2, ...
      ADDED CALLS: ...
      REMOVED CALLS: ...
      <diff body, truncated>

    F4.3 learning: embedder quality tied with our previous minimal
    text — both nomic and mxbai gave identical rankings. The bottleneck
    is the pattern representation, not the embedder. So we enrich here:
    structural signal (function names, call diffs) that survives
    embedding and helps the hunter's recall_similar_code_pattern queries
    (which also contain function signatures) match more precisely.
    """
    parts: list[str] = []
    if advisory.get("summary"):
        parts.append(advisory["summary"][:400])
    cwes = advisory.get("cwe_ids") or []
    if cwes:
        parts.append("CWE: " + ",".join(cwes))
    if diff_data.get("subject"):
        parts.append("FIX: " + diff_data["subject"][:200])
    parts.append("---")
    for f in (diff_data.get("files") or [])[:3]:
        parts.append(f"FILE: {f.get('path', '?')}")
        added = f.get("added_calls") or []
        removed = f.get("removed_calls") or []
        if added:
            parts.append("ADDED CALLS: " + ", ".join(added[:8]))
        if removed:
            parts.append("REMOVED CALLS: " + ", ".join(removed[:8]))
        d = f.get("diff", "")
        if d:
            parts.append(d)
    text = "\n".join(parts)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n[... truncated for embedding ...]"
    return text


def enrich_one(
    advisory: dict,
    *,
    max_commits: int = 1,
    max_files_per_commit: int = _DEFAULT_PER_COMMIT_FILES,
) -> list[EnrichedEntry]:
    """Fetch diffs for one advisory. Returns 0..max_commits entries."""
    fix_commits = advisory.get("fix_commits") or []
    if not fix_commits:
        return []

    entries: list[EnrichedEntry] = []
    for commit in fix_commits[:max_commits]:
        owner = commit.get("owner", "")
        repo = commit.get("repo", "")
        sha = commit.get("sha", "")
        if not (owner and repo and sha):
            continue

        repo_path = _ensure_repo_cloned(owner, repo)
        if not repo_path:
            continue

        if not _ensure_sha_available(repo_path, sha):
            logger.info("sha %s not reachable in %s/%s, skip", sha[:10], owner, repo)
            continue

        try:
            raw = _git_diff_fix_impl(repo_path, sha)
            diff = json.loads(raw)
        except Exception as e:
            logger.warning("git_diff_fix failed on %s/%s@%s: %s", owner, repo, sha[:10], e)
            continue
        if "error" in diff:
            continue

        # Cap files per commit to keep corpus entries bounded
        diff["files"] = (diff.get("files") or [])[:max_files_per_commit]

        entry = EnrichedEntry(
            ghsa_id=advisory.get("ghsa_id", ""),
            cve_id=advisory.get("cve_id", ""),
            cwe_ids=advisory.get("cwe_ids", []),
            summary=advisory.get("summary", ""),
            severity=advisory.get("severity", ""),
            ecosystem=advisory.get("ecosystem", ""),
            package=advisory.get("package", ""),
            commit_sha=sha,
            repo=f"{owner}/{repo}",
            subject=diff.get("subject", ""),
            files=diff["files"],
            pattern=_build_pattern_text(advisory, diff),
        )
        entries.append(entry)
    return entries


def enrich_batch(
    advisories: Iterable[dict],
    *,
    out_path: str,
    max_commits: int = 1,
    max_files_per_commit: int = _DEFAULT_PER_COMMIT_FILES,
    progress_every: int = 10,
) -> dict[str, Any]:
    """Enrich a batch of advisories; write enriched entries as JSONL.

    Returns summary stats.
    """
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    written = 0
    failed = 0
    t0 = time.time()
    with out.open("w", encoding="utf-8") as f:
        for i, adv in enumerate(advisories, 1):
            total += 1
            try:
                entries = enrich_one(
                    adv,
                    max_commits=max_commits,
                    max_files_per_commit=max_files_per_commit,
                )
            except Exception as e:
                logger.exception("enrich failed on %s: %s", adv.get("ghsa_id"), e)
                failed += 1
                continue
            for e in entries:
                f.write(json.dumps(e.to_dict(), ensure_ascii=False) + "\n")
                written += 1
            if i % progress_every == 0:
                logger.info(
                    "progress: %d advisories, %d entries, %d failures, %.1fs",
                    i,
                    written,
                    failed,
                    time.time() - t0,
                )

    return {
        "advisories_processed": total,
        "entries_written": written,
        "failures": failed,
        "duration_s": round(time.time() - t0, 1),
        "output": str(out),
    }
