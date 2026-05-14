"""F143 — ``kryon queue`` subcommand."""

from __future__ import annotations

import argparse
import sys


def add_queue_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("queue", help="F143 — Multi-target engagement queue")
    sub = p.add_subparsers(dest="queue_action", required=True)

    add = sub.add_parser("add", help="Enqueue a target")
    add.add_argument("--target", required=True)
    add.add_argument("--objective", default="")
    add.add_argument("--priority", type=int, default=50)

    listp = sub.add_parser("list", help="List queue items")
    listp.add_argument("--status", default="", help="Filter (pending/running/completed/failed)")

    rm = sub.add_parser("remove", help="Remove an item")
    rm.add_argument("--id", required=True)

    sub.add_parser("purge", help="Drop completed + failed items")
    sub.add_parser("next", help="Show next-due item")
    return p


def _format_table(items) -> str:
    if not items:
        return "(no items)"
    lines = [
        f"{'ID':14s}  {'STATUS':10s}  {'PRIO':5s}  {'TARGET':36s}  OBJECTIVE",
        "-" * 110,
    ]
    for i in items:
        lines.append(f"{i.item_id:14s}  {i.status:10s}  {i.priority:>5}  {i.target[:36]:36s}  {i.objective[:40]}")
    return "\n".join(lines)


def run_queue_command(args) -> int:
    from kryon.queue import EngagementQueue

    q = EngagementQueue.load()
    action = args.queue_action

    if action == "add":
        item = q.add(args.target, objective=args.objective, priority=args.priority)
        q.save()
        print(f"queued {item.item_id} (target={item.target})")
        return 0

    if action == "list":
        items = q.list(status=args.status or None)
        print(_format_table(items))
        return 0

    if action == "remove":
        removed = q.remove(args.id)
        if not removed:
            print(f"no such item '{args.id}'", file=sys.stderr)
            return 1
        q.save()
        print(f"removed {args.id}")
        return 0

    if action == "purge":
        n = q.purge_completed()
        q.save()
        print(f"purged {n} item(s)")
        return 0

    if action == "next":
        nxt = q.next_due()
        if nxt is None:
            print("(queue empty)")
            return 0
        print(_format_table([nxt]))
        return 0

    print(f"queue: unknown action '{action}'", file=sys.stderr)
    return 2
