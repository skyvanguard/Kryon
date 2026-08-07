"""F129 — Cross-engagement audit aggregator.

Walks a directory of ``.kryon/audit/*.jsonl`` files (one per
engagement, written by ``ActionLog``) and produces a roll-up report:
how many engagements, how many tool calls, what was each phase's
status distribution, which tools got used the most, total
redactions, average duration per phase. Useful for:

  - Weekly ops review: "what did Kryon do this week?"
  - SOC handoff: "show me every engagement that touched production
    cardholder data" (filter on redaction_count > 0).
  - Trend tracking: are we hitting more circuit breakers over time?

The aggregator is intentionally cheap — single pass, no DB. Each
file is parsed line by line so a multi-GB audit directory doesn't
blow up memory. Malformed lines are skipped (logged as warnings).

Time-window filtering uses the entry ``timestamp`` (ISO-8601, the
form ``ActionLog.append`` writes: ``YYYY-MM-DDTHH:MM:SSZ``). Pass
``since=`` / ``until=`` as timezone-aware ``datetime`` objects to
narrow the window.

Usage:

    from kryon.audit.aggregator import aggregate_audit_logs, format_report

    report = aggregate_audit_logs(
        audit_dir="/workspace/.kryon/audit/",
        since=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )
    print(format_report(report))
    json.dump(report.to_dict(), f)
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AggregateReport:
    """Roll-up of audit JSONL files across engagements."""

    engagements: int = 0
    tool_calls: int = 0
    phase_status_counts: dict[str, int] = field(default_factory=dict)
    tool_frequency: dict[str, int] = field(default_factory=dict)
    avg_duration_ms_per_phase: dict[str, int] = field(default_factory=dict)
    total_redactions: int = 0
    engagement_ids: list[str] = field(default_factory=list)
    window_start: str | None = None
    window_end: str | None = None

    def top_tools(self, n: int = 10) -> list[tuple[str, int]]:
        return sorted(self.tool_frequency.items(), key=lambda kv: kv[1], reverse=True)[:n]

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagements": self.engagements,
            "tool_calls": self.tool_calls,
            "phase_status_counts": dict(self.phase_status_counts),
            "tool_frequency": dict(self.tool_frequency),
            "avg_duration_ms_per_phase": dict(self.avg_duration_ms_per_phase),
            "total_redactions": self.total_redactions,
            "engagement_ids": list(self.engagement_ids),
            "top_tools": self.top_tools(10),
            "window_start": self.window_start,
            "window_end": self.window_end,
        }


def _parse_timestamp(s: str) -> datetime | None:
    """Parse the ``ActionLog`` timestamp format (``YYYY-MM-DDTHH:MM:SSZ``).
    Returns None when the value is unparseable so the caller can skip
    the entry without aborting the aggregation."""
    if not s:
        return None
    try:
        # Replace trailing Z with +00:00 for fromisoformat (Python < 3.11).
        normalised = s.replace("Z", "+00:00") if s.endswith("Z") else s
        dt = datetime.fromisoformat(normalised)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _in_window(ts: datetime | None, since: datetime | None, until: datetime | None) -> bool:
    """Inclusive lower bound, exclusive upper bound — the typical
    interval semantics for log filters."""
    if ts is None:
        return False
    if since is not None and ts < since:
        return False
    if until is not None and ts >= until:
        return False
    return True


def _is_complete_entry(entry: dict[str, Any]) -> bool:
    """A minimal check — the entry needs the fields the aggregator
    actually reads. Loose so future schema additions don't break older
    aggregations."""
    required = {"timestamp", "engagement_id", "phase", "tool_name", "status"}
    return required.issubset(entry)


def aggregate_audit_logs(
    audit_dir: str | Path,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
) -> AggregateReport:
    """Aggregate every ``*.jsonl`` audit file under ``audit_dir``.

    Args:
        audit_dir: directory containing ``.jsonl`` files.
        since:     optional inclusive lower bound (timezone-aware datetime).
        until:     optional exclusive upper bound (timezone-aware datetime).

    Returns:
        ``AggregateReport`` with counts + top tools + redaction totals.
    """
    p = Path(audit_dir)
    report = AggregateReport(
        window_start=since.isoformat() if since else None,
        window_end=until.isoformat() if until else None,
    )

    if not p.exists() or not p.is_dir():
        return report

    durations: dict[str, list[int]] = defaultdict(list)
    engagement_set: set[str] = set()
    phase_status: Counter[str] = Counter()
    tool_freq: Counter[str] = Counter()

    for jsonl_file in sorted(p.glob("*.jsonl")):
        try:
            with jsonl_file.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        logger.debug("skipping malformed line in %s", jsonl_file.name)
                        continue
                    if not isinstance(entry, dict) or not _is_complete_entry(entry):
                        logger.debug("skipping incomplete entry in %s", jsonl_file.name)
                        continue

                    ts = _parse_timestamp(str(entry.get("timestamp", "")))
                    if not _in_window(ts, since, until):
                        continue

                    report.tool_calls += 1
                    engagement_set.add(str(entry.get("engagement_id", "")))

                    status = str(entry.get("status", "unknown"))
                    phase_status[status] += 1

                    tool_name = str(entry.get("tool_name", "unknown"))
                    tool_freq[tool_name] += 1

                    phase_name = str(entry.get("phase", "unknown"))
                    dur = int(entry.get("duration_ms", 0) or 0)
                    if dur > 0:
                        durations[phase_name].append(dur)

                    report.total_redactions += int(entry.get("redaction_count", 0) or 0)
        except OSError as exc:
            logger.warning("could not read %s: %s", jsonl_file, exc)
            continue

    report.engagements = len(engagement_set)
    report.engagement_ids = sorted(engagement_set)
    report.phase_status_counts = dict(phase_status)
    report.tool_frequency = dict(tool_freq)
    report.avg_duration_ms_per_phase = {phase: sum(samples) // len(samples) for phase, samples in durations.items()}

    return report


def format_report(report: AggregateReport, *, top_n: int = 10) -> str:
    """Human-readable rendering. JSON output is via ``report.to_dict()``."""
    lines: list[str] = []
    lines.append("Kryon Audit Aggregate Report")
    lines.append("=" * 60)
    if report.window_start or report.window_end:
        lines.append(f"Window: {report.window_start or '−∞'} → {report.window_end or '+∞'}")
    lines.append(f"Engagements:     {report.engagements}")
    lines.append(f"Tool calls:      {report.tool_calls}")
    lines.append(f"Total redactions:{report.total_redactions}")
    lines.append("")
    if report.engagement_ids:
        lines.append("Engagement IDs:")
        for eid in report.engagement_ids:
            lines.append(f"  - {eid}")
        lines.append("")
    if report.phase_status_counts:
        lines.append("Phase status distribution:")
        for status, count in sorted(report.phase_status_counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {status:12s} {count}")
        lines.append("")
    top = report.top_tools(top_n)
    if top:
        lines.append(f"Top {len(top)} tool(s) by frequency:")
        for tool, count in top:
            lines.append(f"  {tool:32s} {count}")
        lines.append("")
    if report.avg_duration_ms_per_phase:
        lines.append("Avg duration per phase (ms):")
        for phase, ms in sorted(report.avg_duration_ms_per_phase.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {phase:20s} {ms}")
    return "\n".join(lines)
