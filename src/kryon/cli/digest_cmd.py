"""F141 — ``kryon digest`` subcommand."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone


def add_digest_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("digest", help="F141 — Cross-engagement executive digest")
    p.add_argument("--dir", default=".kryon/audit", help="Audit JSONL directory")
    p.add_argument("--since", default="", help="Inclusive lower bound (YYYY-MM-DD or ISO)")
    p.add_argument("--until", default="", help="Exclusive upper bound (YYYY-MM-DD or ISO)")
    p.add_argument("--format", choices=("markdown", "slack", "json"), default="markdown")
    p.add_argument("--top-tools", type=int, default=5)
    return p


def _parse_dt(s: str) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    if len(s) == 10 and s[4] == "-" and s[7] == "-":
        try:
            return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    try:
        norm = s.replace("Z", "+00:00") if s.endswith("Z") else s
        dt = datetime.fromisoformat(norm)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def run_digest_command(args) -> int:
    from kryon.notifications.exec_digest import build_digest, render_digest

    since = _parse_dt(args.since)
    until = _parse_dt(args.until)
    if args.since and since is None:
        print(f"digest: could not parse --since '{args.since}'", file=sys.stderr)
        return 2
    if args.until and until is None:
        print(f"digest: could not parse --until '{args.until}'", file=sys.stderr)
        return 2

    digest = build_digest(audit_dir=args.dir, since=since, until=until, top_n=args.top_tools)
    print(render_digest(digest, fmt=args.format))
    return 0
