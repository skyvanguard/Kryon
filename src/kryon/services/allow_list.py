"""F10.1 — per-engagement allow-list for suppressing known-FP findings.

Workflow:
  1. Analyst runs scan, marks recurring FPs via `/allow add` (REPL).
  2. Kryon writes entries to `.kryon-allow.yaml` in the target repo root.
  3. Subsequent scans load the file and mark matching findings with
     `_suppressed_by_allowlist`. Suppressed findings DO NOT disappear
     from the output unless the report consumer explicitly filters them.
  4. Every applied suppression is written (append-only) to
     `.kryon-allow-audit.jsonl` so a post-incident review can see what
     was hidden and why.

Schema (.kryon-allow.yaml):

    suppressions:
      - file: "src/util/*.c"        # glob, relative to repo root
        rule: "insecure-use-memset" # rule_id exact match OR empty = any
        line: [40, 200]             # optional line range, inclusive
        reason: "verified safe"     # REQUIRED — empty reason = invalid entry
        added_by: "analyst 2026-04-15"  # free-form, audit breadcrumb

Safety invariants:
  - Reason is REQUIRED. Empty-reason entries are rejected at load time.
  - Audit log entries are append-only; never mutate existing lines.
  - Audit log path is NOT the same file as the YAML — tampering with
    YAML can hide new suppressions but NOT past ones.
  - `--show-suppressed` (hunt report consumer) still lists every
    suppressed finding under a separate header.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)

_DEFAULT_YAML_NAME = ".kryon-allow.yaml"
_DEFAULT_AUDIT_NAME = ".kryon-allow-audit.jsonl"


@dataclass(frozen=True)
class SuppressionRule:
    file_glob: str
    rule_id: str  # empty string = match any rule
    line_lo: int  # 0 = no lower bound
    line_hi: int  # 0 = no upper bound
    reason: str
    added_by: str = ""


@dataclass
class AllowList:
    """Loaded allow-list + its source path + audit log path."""

    rules: list[SuppressionRule] = field(default_factory=list)
    repo_root: Path = field(default_factory=lambda: Path("."))
    audit_path: Path = field(default_factory=lambda: Path("."))

    def _match(self, rule: SuppressionRule, file_path: str, rule_id: str, line: int) -> bool:
        # file glob: the finding path is absolute; compare against
        # repo-relative form when possible.
        rel = _make_relative(file_path, self.repo_root)
        if rule.file_glob and not fnmatch.fnmatch(rel, rule.file_glob):
            return False
        if rule.rule_id and rule.rule_id != rule_id:
            return False
        if rule.line_lo and line and line < rule.line_lo:
            return False
        if rule.line_hi and line and line > rule.line_hi:
            return False
        return True

    def match(self, file_path: str, rule_id: str, line: int = 0) -> SuppressionRule | None:
        """Return the first matching rule, or None."""
        for r in self.rules:
            if self._match(r, file_path, rule_id, line):
                return r
        return None

    def annotate(self, findings: Iterable[dict]) -> list[dict]:
        """Stamp every finding with `_suppressed_by_allowlist` when matched.
        Findings are NOT removed. Consumer filters if it wants to hide them.
        Every match is written to the audit log (append-only)."""
        out = []
        hits: list[dict] = []
        for f in findings:
            fp = f.get("file_path", "")
            rule_id = f.get("_semgrep_rule_id") or f.get("_pattern") or f.get("_joern_rule_id") or ""
            line = _parse_line(f.get("line_range") or "0")
            m = self.match(fp, rule_id, line)
            if m is not None:
                f["_suppressed_by_allowlist"] = {
                    "file_glob": m.file_glob,
                    "rule_id": m.rule_id,
                    "reason": m.reason,
                    "added_by": m.added_by,
                }
                hits.append(
                    {
                        "ts": int(time.time()),
                        "file": fp,
                        "rule_id": rule_id,
                        "line": line,
                        "cwe": f.get("cwe", ""),
                        "matched_glob": m.file_glob,
                        "matched_rule_id": m.rule_id,
                        "reason": m.reason,
                    }
                )
            out.append(f)
        if hits:
            _append_audit(self.audit_path, hits)
        return out


def _parse_line(s: str) -> int:
    s = str(s or "").lstrip("~").strip()
    if not s:
        return 0
    try:
        return int(s.split("-", 1)[0])
    except ValueError:
        return 0


def _make_relative(abs_or_rel: str, root: Path) -> str:
    """Return path relative to `root` when possible, else the basename."""
    try:
        p = Path(abs_or_rel).resolve()
        return str(p.relative_to(root.resolve()))
    except (ValueError, OSError):
        return Path(abs_or_rel).name


def _append_audit(path: Path, records: list[dict]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
    except OSError as exc:
        logger.warning("allow-list audit write failed: %s", exc)


def _parse_entry(raw: dict) -> SuppressionRule | None:
    """Validate one YAML entry. Returns None if invalid (reason missing)."""
    reason = str(raw.get("reason") or "").strip()
    if not reason:
        logger.warning("allow-list entry missing reason, skipping: %r", raw)
        return None
    line = raw.get("line") or []
    line_lo, line_hi = 0, 0
    if isinstance(line, (list, tuple)) and len(line) >= 1:
        try:
            line_lo = int(line[0])
            line_hi = int(line[1]) if len(line) > 1 else line_lo
        except (TypeError, ValueError):
            line_lo = line_hi = 0
    return SuppressionRule(
        file_glob=str(raw.get("file") or "").strip(),
        rule_id=str(raw.get("rule") or "").strip(),
        line_lo=line_lo,
        line_hi=line_hi,
        reason=reason,
        added_by=str(raw.get("added_by") or "").strip(),
    )


def load(repo_root: str | Path) -> AllowList:
    """Load .kryon-allow.yaml from repo_root. Missing file = empty list."""
    root = Path(repo_root).resolve()
    yaml_path = root / _DEFAULT_YAML_NAME
    audit_path = root / _DEFAULT_AUDIT_NAME

    rules: list[SuppressionRule] = []
    if yaml_path.is_file():
        try:
            import yaml  # PyYAML — already a transitive dep via semgrep

            doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            logger.warning("allow-list YAML parse failed at %s: %s", yaml_path, exc)
            doc = {}
        for entry in doc.get("suppressions") or []:
            if not isinstance(entry, dict):
                continue
            rule = _parse_entry(entry)
            if rule is not None:
                rules.append(rule)
    return AllowList(rules=rules, repo_root=root, audit_path=audit_path)


def add_entry(
    repo_root: str | Path,
    *,
    file_glob: str,
    rule_id: str = "",
    line_range: tuple[int, int] | None = None,
    reason: str,
    added_by: str = "",
) -> Path:
    """Append a new suppression to .kryon-allow.yaml. Reason required.

    Returns the YAML path that was written.
    """
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("reason is required for allow-list entries")
    root = Path(repo_root).resolve()
    yaml_path = root / _DEFAULT_YAML_NAME
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML not installed — cannot write allow-list") from exc

    doc: dict = {}
    if yaml_path.is_file():
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    suppressions = doc.setdefault("suppressions", [])
    entry: dict = {"file": file_glob, "reason": reason}
    if rule_id:
        entry["rule"] = rule_id
    if line_range and line_range[0]:
        entry["line"] = [int(line_range[0]), int(line_range[1] or line_range[0])]
    if added_by:
        entry["added_by"] = added_by
    suppressions.append(entry)
    yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return yaml_path
