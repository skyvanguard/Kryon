"""F143 + F196 — ``kryon queue`` subcommand.

F143 introduced add/list/remove/purge/next. F196 closes the loop with
``process`` that drains pending items by invoking ``kryon engage`` per
target. Banca-safe defaults: concurrency 1 (serial), no auto-retry on
failure (items stay in `failed` state for operator triage).
"""

from __future__ import annotations

import argparse
import logging
import os
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


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

    # F196 — Drain pending items by calling `kryon engage` per target.
    proc = sub.add_parser("process", help="F196 — Drain queue invoking `kryon engage` per item")
    proc.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Parallel workers (default: 1 for banca-safe serial execution)",
    )
    proc.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Stop after processing N items (0 = drain everything pending)",
    )
    proc.add_argument(
        "--framework",
        default="",
        help="Comma-separated frameworks to pass to engage --framework",
    )
    proc.add_argument(
        "--orchestrated",
        action="store_true",
        help="Pass --orchestrated to each engage invocation",
    )
    proc.add_argument(
        "--auto-approve",
        action="store_true",
        help="Pass --auto-approve to each engage invocation (lab/POC only)",
    )
    proc.add_argument(
        "--dry-run-only",
        action="store_true",
        help="Pass --dry-run-only to each engage invocation",
    )
    proc.add_argument(
        "--out",
        default="",
        help="Output directory root; each item writes to <out>/<item_id>/",
    )
    proc.add_argument(
        "--client",
        default="",
        help="Pass --client to each engage invocation",
    )
    proc.add_argument(
        "--consolidate",
        action="store_true",
        help="After draining, merge all per-host findings into ONE consolidated "
        "spreadsheet + segment summary under --out (needs --out).",
    )
    proc.add_argument(
        "--ssh-key",
        default="",
        help="SSH key path for compliance runner per engage invocation",
    )
    proc.add_argument(
        "--engage-bin",
        default="",
        help="Override the kryon binary used for child engage calls "
        "(default: argv[0] of the parent process or `kryon` in PATH)",
    )
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


def _resolve_engage_bin(explicit: str) -> list[str]:
    """Return the argv prefix used to invoke a child engage process.

    Order of precedence:
      1. `--engage-bin` CLI flag
      2. `KRYON_ENGAGE_BIN` env (so containerised runs can pin it)
      3. `kryon` resolved from PATH

    Returns argv as a list (not a string) to avoid quoting issues.
    """
    if explicit:
        return shlex.split(explicit)
    env_bin = os.environ.get("KRYON_ENGAGE_BIN", "").strip()
    if env_bin:
        return shlex.split(env_bin)
    return ["kryon"]


def _build_engage_argv(
    *,
    engage_bin: list[str],
    target: str,
    objective: str,
    framework: str,
    orchestrated: bool,
    auto_approve: bool,
    dry_run_only: bool,
    out_dir: str,
    client: str,
    ssh_key: str,
    item_id: str,
) -> list[str]:
    """Compose the `kryon engage` argv for a single queue item."""
    argv: list[str] = [*engage_bin, "engage", target]
    if objective:
        argv.extend(["--objective", objective])
    if framework:
        argv.extend(["--framework", framework])
    if orchestrated:
        argv.append("--orchestrated")
    if auto_approve:
        argv.append("--auto-approve")
    if dry_run_only:
        argv.append("--dry-run-only")
    if out_dir:
        argv.extend(["--out", os.path.join(out_dir, item_id)])
    if client:
        argv.extend(["--client", client])
    if ssh_key:
        argv.extend(["--ssh-key", ssh_key])
    argv.extend(["--engagement-id", item_id])
    return argv


def _run_one(argv: list[str], item_id: str) -> tuple[str, int, str]:
    """Run one engage invocation. Returns (item_id, exit_code, stderr_tail).

    Never raises — failures surface via exit code so the worker pool
    can drain the rest of the queue.
    """
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            check=False,
        )
        stderr_tail = (proc.stderr or "").strip().splitlines()[-1] if proc.stderr else ""
        return item_id, proc.returncode, stderr_tail[:200]
    except (OSError, subprocess.SubprocessError) as exc:
        return item_id, 127, f"spawn failed: {exc}"[:200]


def _process_queue(args) -> int:
    """F196 — Drain pending items by spawning `kryon engage` per target.

    Banca-safe defaults: concurrency 1, no auto-retry. Items that fail
    stay in `failed` status so the operator can triage them.
    """
    from kryon.queue import EngagementQueue

    engage_bin = _resolve_engage_bin(args.engage_bin)
    concurrency = max(1, args.concurrency)
    limit = max(0, args.limit)

    q = EngagementQueue.load()
    pending = [i for i in q.items if i.status == "pending"]
    if not pending:
        print("(no pending items)")
        return 0

    if limit:
        pending = pending[:limit]

    # Sort by (priority asc, queued_at asc) so highest-priority items
    # run first when concurrency=1.
    pending.sort(key=lambda x: (x.priority, x.queued_at))

    print(
        f"processing {len(pending)} item(s) with concurrency={concurrency} "
        f"(framework={args.framework or '-'}, orchestrated={args.orchestrated})"
    )

    succeeded = 0
    failed = 0

    def _claim_and_build(item):
        q.mark_started(item.item_id)
        q.save()
        argv = _build_engage_argv(
            engage_bin=engage_bin,
            target=item.target,
            objective=item.objective,
            framework=args.framework,
            orchestrated=args.orchestrated,
            auto_approve=args.auto_approve,
            dry_run_only=args.dry_run_only,
            out_dir=args.out,
            client=args.client,
            ssh_key=args.ssh_key,
            item_id=item.item_id,
        )
        return argv

    if concurrency == 1:
        for item in pending:
            argv = _claim_and_build(item)
            print(f"  → {item.item_id} {item.target}")
            _, rc, err = _run_one(argv, item.item_id)
            ok = rc == 0
            q.mark_finished(item.item_id, ok=ok, error=err if not ok else "")
            q.save()
            if ok:
                print(f"    ✓ completed ({item.item_id})")
                succeeded += 1
            else:
                print(f"    ✗ failed exit={rc} ({item.item_id}) {err}")
                failed += 1
    else:
        # Parallel — claim all first to avoid worker contention on save().
        argvs: dict[str, list[str]] = {}
        for item in pending:
            argvs[item.item_id] = _claim_and_build(item)

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(_run_one, argv, iid): iid for iid, argv in argvs.items()}
            for fut in as_completed(futures):
                iid, rc, err = fut.result()
                ok = rc == 0
                q.mark_finished(iid, ok=ok, error=err if not ok else "")
                q.save()
                if ok:
                    print(f"  ✓ {iid} completed")
                    succeeded += 1
                else:
                    print(f"  ✗ {iid} failed exit={rc} {err}")
                    failed += 1

    print(f"done. succeeded={succeeded}, failed={failed}")

    # F1.1 — Consolidate the per-host outputs into ONE client deliverable.
    if getattr(args, "consolidate", False):
        if not args.out:
            print("  [consolidate] skipped: --consolidate needs --out", file=sys.stderr)
        else:
            from pathlib import Path

            from kryon.reporting.consolidate import consolidate_engagement_dir

            result = consolidate_engagement_dir(Path(args.out), client_name=args.client)
            summary = result["summary"]
            print(
                f"  consolidated: {summary['total_findings']} findings across "
                f"{summary['host_count']} host(s) → {result['spreadsheet']}"
            )
            print(f"  segment summary → {result['summary_json']}")

    return 0 if failed == 0 else 1


def run_queue_command(args) -> int:
    from kryon.queue import EngagementQueue

    action = args.queue_action

    if action == "process":
        return _process_queue(args)

    q = EngagementQueue.load()

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
