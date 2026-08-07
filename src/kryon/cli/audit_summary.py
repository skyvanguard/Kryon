"""F129 — `kryon audit-summary` subcommand.

Reads ``.kryon/audit/*.jsonl`` (one file per engagement) and prints
a roll-up. Useful for weekly ops reviews and SOC handoffs.

Usage:

    kryon audit-summary --dir /workspace/.kryon/audit/
    kryon audit-summary --dir ./.kryon/audit/ --since 2026-05-01
    kryon audit-summary --dir ./audit/ --format json > summary.json
    kryon audit-summary --dir ./audit/ --top-tools 5
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from kryon.audit.aggregator import aggregate_audit_logs, format_report


def add_audit_summary_subparser(subparsers) -> argparse.ArgumentParser:
    """Register the ``audit-summary`` subcommand on the main parser."""
    p = subparsers.add_parser(
        "audit-summary",
        help="F129 — Aggregate Kryon engagement audit logs (cross-engagement view)",
    )
    p.add_argument(
        "--dir",
        required=True,
        help="Directory containing per-engagement audit *.jsonl files",
    )
    p.add_argument(
        "--since",
        default="",
        help="Inclusive lower bound (YYYY-MM-DD or ISO-8601 datetime). UTC assumed if no tz.",
    )
    p.add_argument(
        "--until",
        default="",
        help="Exclusive upper bound (YYYY-MM-DD or ISO-8601 datetime). UTC assumed if no tz.",
    )
    p.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help='Output format: human-readable "table" (default) or "json" for piping.',
    )
    p.add_argument(
        "--top-tools",
        type=int,
        default=10,
        help="How many top-frequency tools to render (default 10)",
    )
    return p


def _parse_arg_datetime(s: str) -> datetime | None:
    """Parse user-supplied date/time. Bare YYYY-MM-DD → midnight UTC."""
    s = (s or "").strip()
    if not s:
        return None
    # Accept "YYYY-MM-DD" → start of day UTC.
    if len(s) == 10 and s[4] == "-" and s[7] == "-":
        try:
            return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    # Accept ISO-8601 with optional Z suffix.
    try:
        normalised = s.replace("Z", "+00:00") if s.endswith("Z") else s
        dt = datetime.fromisoformat(normalised)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def run_audit_summary(args) -> int:
    since = _parse_arg_datetime(args.since)
    until = _parse_arg_datetime(args.until)

    if args.since and since is None:
        print(f"audit-summary: could not parse --since '{args.since}'", file=sys.stderr)
        return 2
    if args.until and until is None:
        print(f"audit-summary: could not parse --until '{args.until}'", file=sys.stderr)
        return 2

    report = aggregate_audit_logs(args.dir, since=since, until=until)

    if args.format == "json":
        payload = report.to_dict()
        payload["top_tools"] = report.top_tools(args.top_tools)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(format_report(report, top_n=args.top_tools))
    return 0
