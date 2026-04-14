"""
GitHub Advisory Database scraper — the foundation of F4.1.

The github/advisory-database repo (GNU AGPL) mirrors the entire GHSA
database as JSON files. We clone it shallowly, walk the tree, and
emit normalized records that the enrichment step can turn into
CVE-with-diff RAG entries.

Output schema (one dict per advisory):
  {
    "ghsa_id":   "GHSA-xxxx-yyyy-zzzz",
    "cve_id":    "CVE-YYYY-NNNN" | "",
    "cwe_ids":   ["CWE-787", ...],
    "summary":   "short title",
    "severity":  "HIGH" | "CRITICAL" | ...,
    "ecosystem": "pip" | "npm" | "maven" | "go" | "rubygems" | "nuget" | "cargo",
    "package":   "name",
    "fixed_in":  "1.2.3",
    "vulnerable_range": "<1.2.3",
    "references": ["https://github.com/owner/repo/commit/SHA", ...],
    "fix_commits": [{"owner": "x", "repo": "y", "sha": "SHA"}, ...],
    "published":  "2024-01-01",
  }

A second pass (cve_diff_enricher) fetches each fix_commit's diff via
git clone + our existing git_diff_fix tool, producing the final
{before_code, after_code, function_name, ...} records for RAG.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from kryon.knowledge.scrapers.base_scraper import BaseScraper

logger = logging.getLogger(__name__)

# Default location for the cloned DB — large (~300 MB), persist it.
_DB_PATH = Path(os.environ.get(
    "KRYON_ADVISORY_DB_PATH",
    "/workspace/sources/_advisory_database",
))
_DB_URL = "https://github.com/github/advisory-database.git"

# GitHub commit URL parser
_GH_COMMIT_RE = re.compile(
    r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})",
    re.I,
)
# Also accept pull-request URLs — they contain the fix commit via merge
_GH_PR_RE = re.compile(
    r"https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)",
    re.I,
)
_CWE_RE = re.compile(r"CWE-\d+", re.I)


class GitHubAdvisoryScraper(BaseScraper):
    """Scrape the github/advisory-database into normalized JSONL."""

    def get_source_name(self) -> str:
        return "github-advisory-database"

    # ------------------------------------------------------------------

    def _clone_or_update(self) -> Path:
        """Clone the DB shallowly, or pull if already present."""
        if _DB_PATH.exists():
            logger.info("Advisory DB present at %s, pulling updates...", _DB_PATH)
            r = subprocess.run(
                ["git", "pull", "--ff-only", "--depth", "1"],
                cwd=str(_DB_PATH), capture_output=True, text=True,
                timeout=600, check=False,
            )
            if r.returncode != 0:
                logger.warning("git pull failed: %s", r.stderr[:200])
        else:
            _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            logger.info("Cloning %s into %s (shallow)...", _DB_URL, _DB_PATH)
            r = subprocess.run(
                ["git", "clone", "--depth", "1", _DB_URL, str(_DB_PATH)],
                capture_output=True, text=True, timeout=900, check=False,
            )
            if r.returncode != 0:
                raise RuntimeError(f"clone failed: {r.stderr[:500]}")
        return _DB_PATH

    # ------------------------------------------------------------------

    @staticmethod
    def _extract_fix_commits(refs: list[str]) -> list[dict[str, str]]:
        """Pull GitHub commit hashes out of the references list."""
        out: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for r in refs:
            m = _GH_COMMIT_RE.search(r)
            if m:
                owner, repo, sha = m.group(1), m.group(2), m.group(3).lower()
                key = (owner, repo, sha[:10])
                if key in seen:
                    continue
                seen.add(key)
                out.append({"owner": owner, "repo": repo, "sha": sha})
        return out

    @staticmethod
    def _parse_one(path: Path) -> dict[str, Any] | None:
        """Parse one advisory JSON file into our normalized schema."""
        try:
            adv = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.debug("skip %s: %s", path.name, e)
            return None

        # Newer advisories use OSV schema — extract key fields
        ghsa_id = adv.get("id") or adv.get("ghsa_id") or ""
        summary = (adv.get("summary") or adv.get("details") or "")[:500]
        severity = ""
        # OSV severity can be in 'database_specific' or 'severity' list
        db_spec = adv.get("database_specific") or {}
        severity = (
            db_spec.get("severity")
            or (adv.get("severity") or [{}])[0].get("type", "")
            or ""
        )

        # CVE id — from aliases
        cve_id = ""
        for alias in (adv.get("aliases") or []):
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        # CWE ids — search whole blob
        blob = json.dumps(adv)
        cwes = sorted(set(_CWE_RE.findall(blob)))

        # References — collect all urls
        refs = [r.get("url", "") for r in (adv.get("references") or [])]
        fix_commits = GitHubAdvisoryScraper._extract_fix_commits(refs)

        # Ecosystem + package (first affected block)
        affected = (adv.get("affected") or [{}])[0]
        pkg = affected.get("package", {}) or {}
        ecosystem = pkg.get("ecosystem", "") or ""
        package = pkg.get("name", "") or ""

        # Vulnerable range + fixed version
        vulnerable_range = ""
        fixed_in = ""
        for r in affected.get("ranges", []) or []:
            for ev in r.get("events", []) or []:
                if "introduced" in ev and ev.get("introduced") != "0":
                    vulnerable_range = f">={ev['introduced']}"
                if "fixed" in ev:
                    fixed_in = ev["fixed"]

        return {
            "ghsa_id":   ghsa_id,
            "cve_id":    cve_id,
            "cwe_ids":   cwes,
            "summary":   summary,
            "severity":  str(severity).upper(),
            "ecosystem": ecosystem,
            "package":   package,
            "fixed_in":  fixed_in,
            "vulnerable_range": vulnerable_range,
            "references": refs[:20],
            "fix_commits": fix_commits,
            "published":  adv.get("published", "") or "",
            "_path":      str(path.relative_to(_DB_PATH)) if _DB_PATH in path.parents else path.name,
        }

    # ------------------------------------------------------------------

    def scrape(
        self,
        *,
        limit: int | None = None,
        require_fix_commit: bool = True,
        ecosystems: list[str] | None = None,
        cwe_filter: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Walk the advisory DB, parse, filter, and return normalized records.

        Args:
            limit: Stop after N matching advisories (None = all).
            require_fix_commit: Skip advisories without a parseable GH commit.
            ecosystems: Only keep these ecosystems (None = all).
            cwe_filter: Only keep advisories whose CWE ids match (None = all).
        """
        db = self._clone_or_update()
        results: list[dict[str, Any]] = []

        # Walk advisories directory tree — structure:
        #   advisories/github-reviewed/YYYY/MM/GHSA-xxxx/GHSA-xxxx.json
        root = db / "advisories"
        if not root.is_dir():
            raise RuntimeError(f"advisories/ not found under {db}")

        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if not name.endswith(".json"):
                    continue
                if not name.startswith("GHSA-"):
                    continue
                rec = self._parse_one(Path(dirpath) / name)
                if rec is None:
                    continue
                if require_fix_commit and not rec["fix_commits"]:
                    continue
                if ecosystems and rec["ecosystem"].lower() not in {
                    e.lower() for e in ecosystems
                }:
                    continue
                if cwe_filter:
                    want = {c.upper() for c in cwe_filter}
                    have = {c.upper() for c in rec["cwe_ids"]}
                    if not (want & have):
                        continue
                results.append(rec)
                self.scraped_count += 1
                if limit and len(results) >= limit:
                    return results

        return results


# ---------------------------------------------------------------------------
# Convenience: write to JSONL
# ---------------------------------------------------------------------------


def write_jsonl(records: list[dict[str, Any]], out_path: str) -> int:
    """Append each record as a JSON line. Returns count written."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return len(records)
