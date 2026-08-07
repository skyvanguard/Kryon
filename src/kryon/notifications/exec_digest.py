"""F141 — Periodic executive digest.

Builds a weekly / monthly cross-engagement summary on top of the F129
``aggregate_audit_logs`` data. Emits Markdown by default (suitable for
email or Slack mrkdwn). Plain ``slack`` mode produces the same content
wrapped in Slack-friendly headings.

Designed to run from cron:

    kryon digest --since 2026-05-08 --until 2026-05-15 --format slack \
        | curl -X POST $KRYON_SLACK_WEBHOOK \
               -H 'content-type: application/json' \
               -d @-

Or as part of ``kryon schedule run-due`` when a digest job fires.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from kryon.audit.aggregator import aggregate_audit_logs


@dataclass
class ExecDigest:
    """Structured digest payload — easy to render in any format."""

    window_start: str
    window_end: str
    engagements: int
    tool_calls: int
    failed_phases: int
    total_redactions: int
    top_tools: list[tuple[str, int]]
    avg_duration_per_phase: dict[str, int]
    engagement_ids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_start": self.window_start,
            "window_end": self.window_end,
            "engagements": self.engagements,
            "tool_calls": self.tool_calls,
            "failed_phases": self.failed_phases,
            "total_redactions": self.total_redactions,
            "top_tools": self.top_tools,
            "avg_duration_per_phase": self.avg_duration_per_phase,
            "engagement_ids": self.engagement_ids,
        }


def build_digest(
    *,
    audit_dir: str | Path,
    since: datetime | None = None,
    until: datetime | None = None,
    top_n: int = 5,
) -> ExecDigest:
    """Aggregate audit JSONLs and pack into ExecDigest."""
    report = aggregate_audit_logs(audit_dir, since=since, until=until)
    failed = int(report.phase_status_counts.get("failed", 0)) + int(report.phase_status_counts.get("aborted", 0))
    return ExecDigest(
        window_start=report.window_start or "−∞",
        window_end=report.window_end or "+∞",
        engagements=report.engagements,
        tool_calls=report.tool_calls,
        failed_phases=failed,
        total_redactions=report.total_redactions,
        top_tools=report.top_tools(top_n),
        avg_duration_per_phase=dict(report.avg_duration_ms_per_phase),
        engagement_ids=list(report.engagement_ids),
    )


def render_markdown(digest: ExecDigest) -> str:
    lines = [
        "# Kryon Executive Digest",
        f"**Window**: {digest.window_start} → {digest.window_end}",
        "",
        f"- **Engagements**: {digest.engagements}",
        f"- **Tool calls**: {digest.tool_calls}",
        f"- **Failed/aborted phases**: {digest.failed_phases}",
        f"- **Sensitive-data redactions**: {digest.total_redactions}",
        "",
    ]
    if digest.top_tools:
        lines.append(f"## Top {len(digest.top_tools)} tools by frequency")
        lines.append("")
        for tool, count in digest.top_tools:
            lines.append(f"- `{tool}`: {count}")
        lines.append("")
    if digest.engagement_ids:
        lines.append("## Engagements")
        lines.append("")
        for eid in digest.engagement_ids[:20]:
            lines.append(f"- {eid}")
        if len(digest.engagement_ids) > 20:
            lines.append(f"- … +{len(digest.engagement_ids) - 20} more")
        lines.append("")
    if digest.avg_duration_per_phase:
        lines.append("## Average duration per phase (ms)")
        lines.append("")
        for phase, ms in sorted(digest.avg_duration_per_phase.items(), key=lambda kv: -kv[1])[:8]:
            lines.append(f"- `{phase}`: {ms} ms")
    return "\n".join(lines)


def render_slack(digest: ExecDigest) -> str:
    """Slack mrkdwn — same content, slightly different formatting."""
    lines = [
        f"*Kryon Executive Digest*  ({digest.window_start} → {digest.window_end})",
        "",
        f"• Engagements: *{digest.engagements}*",
        f"• Tool calls: *{digest.tool_calls}*",
        f"• Failed/aborted phases: *{digest.failed_phases}*",
        f"• Redactions: *{digest.total_redactions}*",
    ]
    if digest.top_tools:
        lines.append("")
        lines.append("*Top tools:*")
        for tool, count in digest.top_tools:
            lines.append(f"  • `{tool}`: {count}")
    if digest.engagement_ids:
        lines.append("")
        sample = ", ".join(digest.engagement_ids[:5])
        more = f" + {len(digest.engagement_ids) - 5} more" if len(digest.engagement_ids) > 5 else ""
        lines.append(f"*Engagements:* {sample}{more}")
    return "\n".join(lines)


def render_digest(digest: ExecDigest, fmt: str = "markdown") -> str:
    fmt = (fmt or "markdown").lower()
    if fmt == "slack":
        return render_slack(digest)
    if fmt == "json":
        import json

        return json.dumps(digest.to_dict(), ensure_ascii=False, indent=2)
    # markdown / email fallback
    return render_markdown(digest)
