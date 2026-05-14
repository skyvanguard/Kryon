"""F133 — Baseline diffing across engagement runs.

Compares the current run's findings against the previous saved
findings.json (via ``EngagementState.findings_path``) and emits a
``BaselineDiff`` with four buckets:

  - **new**     — findings in current that weren't in previous.
  - **gone**    — findings in previous that aren't in current
                  (remediated, or false-positive from last run).
  - **changed** — same ``(rule_id, host)`` pair but the severity
                  bumped (or the evidence changed materially).
  - **stable**  — same finding in both runs (the baseline noise).

The diff is what turns Kryon from a scanner into a monitor: the
operator should care about ``new`` (alert) and ``gone`` (cleanup
evidence), not the noise floor.

Matching key is ``(rule_id, host)``. Same rule on a different host
counts as a different finding (correct: the host context matters).

Pure module, no I/O — the caller reads/writes findings.json.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class BaselineDiff:
    """Outcome of comparing two finding lists by ``(rule_id, host)``."""

    new: list[dict[str, Any]] = field(default_factory=list)
    gone: list[dict[str, Any]] = field(default_factory=list)
    changed: list[dict[str, Any]] = field(default_factory=list)
    stable: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.gone or self.changed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "new": self.new,
            "gone": self.gone,
            "changed": self.changed,
            "stable": self.stable,
            "summary": {
                "new": len(self.new),
                "gone": len(self.gone),
                "changed": len(self.changed),
                "stable": len(self.stable),
            },
        }


def _finding_to_dict(f: Any) -> dict[str, Any]:
    """Coerce a Finding dataclass OR a plain dict into a uniform dict
    shape for diffing. Tolerant of missing fields."""
    if isinstance(f, dict):
        return f
    out = {}
    for attr in (
        "cwe",
        "severity",
        "host",
        "rule_id",
        "message",
        "evidence",
        "remediation",
        "confidence",
        "needs_verification",
    ):
        val = getattr(f, attr, None)
        if val is not None:
            out[attr] = val
    return out


def _key(f: dict[str, Any]) -> tuple[str, str]:
    return (str(f.get("rule_id", "")), str(f.get("host", "")))


def _changed_materially(prev: dict[str, Any], curr: dict[str, Any]) -> bool:
    """A change is material if severity rank moved up/down or the
    evidence text changed by more than whitespace/punctuation."""
    prev_sev = _SEV_RANK.get(str(prev.get("severity", "")).upper(), 99)
    curr_sev = _SEV_RANK.get(str(curr.get("severity", "")).upper(), 99)
    if prev_sev != curr_sev:
        return True
    prev_ev = " ".join(str(prev.get("evidence", "")).split())
    curr_ev = " ".join(str(curr.get("evidence", "")).split())
    return prev_ev != curr_ev


def compute_diff(
    previous_findings: list[Any] | None,
    current_findings: list[Any],
) -> BaselineDiff:
    """Build a ``BaselineDiff`` between two finding lists.

    Args:
        previous_findings: prior run's findings (None / [] => everything is new).
        current_findings:  current run's findings.
    """
    diff = BaselineDiff()
    prev = [_finding_to_dict(f) for f in (previous_findings or [])]
    curr = [_finding_to_dict(f) for f in current_findings]

    prev_by_key = {_key(p): p for p in prev}
    curr_by_key = {_key(c): c for c in curr}

    # NEW + STABLE/CHANGED
    for k, c in curr_by_key.items():
        if k not in prev_by_key:
            diff.new.append(c)
        else:
            p = prev_by_key[k]
            if _changed_materially(p, c):
                diff.changed.append({"previous": p, "current": c})
            else:
                diff.stable.append(c)

    # GONE
    for k, p in prev_by_key.items():
        if k not in curr_by_key:
            diff.gone.append(p)

    return diff


def load_previous_findings(findings_path: str | Path | None) -> list[dict[str, Any]]:
    """Read the previous run's findings.json. Returns an empty list when
    the path is missing / malformed (so the caller treats it as "first
    run" — everything ends up in ``new``)."""
    if not findings_path:
        return []
    p = Path(findings_path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    # The demo_report writes ``{"findings": [...]}`` shape.
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data["findings"]
    if isinstance(data, list):
        return data
    return []


def format_diff_summary(diff: BaselineDiff) -> str:
    """One-line summary suitable for console output."""
    if not diff.has_changes:
        return f"baseline diff: {len(diff.stable)} stable, no changes since last run"
    parts = []
    if diff.new:
        parts.append(f"+{len(diff.new)} NEW")
    if diff.gone:
        parts.append(f"-{len(diff.gone)} GONE")
    if diff.changed:
        parts.append(f"~{len(diff.changed)} CHANGED")
    parts.append(f"={len(diff.stable)} stable")
    return "baseline diff: " + ", ".join(parts)
