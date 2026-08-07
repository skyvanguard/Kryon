"""F144 — ``kryon approve`` subcommand."""

from __future__ import annotations

import argparse
import sys


def add_approve_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("approve", help="F144 — Approve / reject pending destructive actions")
    p.add_argument("action_id", nargs="?", default="", help="Action ID to approve (omit with --list)")
    p.add_argument("--list", dest="list_only", action="store_true", help="List pending actions")
    p.add_argument("--reject", action="store_true", help="Reject instead of approve")
    p.add_argument("--reason", default="", help="Rejection reason")
    p.add_argument("--by", default="operator", help="decided_by label (default: operator)")
    return p


def _format_table(items) -> str:
    if not items:
        return "(no pending actions)"
    lines = [
        f"{'ACTION_ID':14s}  {'RISK':8s}  {'KIND':16s}  {'TARGET':32s}  DESCRIPTION",
        "-" * 110,
    ]
    for a in items:
        lines.append(f"{a.action_id:14s}  {a.risk_level:8s}  {a.kind:16s}  {a.target[:32]:32s}  {a.description[:40]}")
    return "\n".join(lines)


def run_approve_command(args) -> int:
    from kryon.approval import ApprovalQueue

    q = ApprovalQueue.load()

    if args.list_only or (not args.action_id and not args.reject):
        print(_format_table(q.list(status="pending")))
        return 0

    if not args.action_id:
        print("approve: pass action_id or --list", file=sys.stderr)
        return 2

    if args.reject:
        if not q.reject(args.action_id, reason=args.reason, decided_by=args.by):
            print(f"no such pending action '{args.action_id}'", file=sys.stderr)
            return 1
        q.save()
        print(f"rejected {args.action_id} (reason: {args.reason or 'none'})")
        return 0

    if not q.approve(args.action_id, decided_by=args.by):
        print(f"no such pending action '{args.action_id}'", file=sys.stderr)
        return 1
    q.save()
    print(f"approved {args.action_id}")
    return 0
