"""F135 — ``kryon schedule`` subcommand.

Manage per-target scheduled engagements stored in
``.kryon/schedule.json`` (or ``KRYON_SCHEDULE_PATH``). The actual job
execution is the operator's responsibility — pair this with OS cron
/ systemd timer that calls ``kryon schedule run-due`` every minute,
or invoke it from a long-running ``kryon serve`` process.

Sub-actions:

    kryon schedule add --id britimp --target www.britimp.com.py \
                       --cron "0 6 * * *" --objective "audit attack surface"
    kryon schedule list
    kryon schedule remove --id britimp
    kryon schedule run-due [--dry-run]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone

from kryon.scheduler import ScheduledJob, Scheduler


def add_schedule_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(
        "schedule",
        help="F135 — Manage scheduled Kryon engagements (cron-style)",
    )
    sub = p.add_subparsers(dest="schedule_action", required=True)

    add = sub.add_parser("add", help="Add or replace a scheduled engagement")
    add.add_argument("--id", required=True, help="job_id (unique key)")
    add.add_argument("--target", required=True, help="target host/URL")
    add.add_argument("--cron", required=True, help='5-field cron expr, e.g. "0 6 * * *"')
    add.add_argument("--objective", default="", help="--objective text passed to engage")

    sub.add_parser("list", help="List every scheduled job")

    rm = sub.add_parser("remove", help="Remove a scheduled job by id")
    rm.add_argument("--id", required=True)

    runner = sub.add_parser("run-due", help="Run every job whose cron matches now")
    runner.add_argument("--dry-run", action="store_true", help="Print what would run; don't fork engage")
    runner.add_argument(
        "--watch",
        action="store_true",
        help="Q2 — Stay running as a continuous monitor: check due jobs every --interval seconds.",
    )
    runner.add_argument("--interval", type=int, default=60, help="Seconds between checks in --watch mode (default 60)")
    runner.add_argument(
        "--notify-drift",
        action="store_true",
        help="Q2 — Pass --notify-drift to each engage so scheduled runs alert on drift.",
    )

    return p


def _format_table(jobs) -> str:
    if not jobs:
        return "(no scheduled jobs)"
    lines = [
        f"{'JOB_ID':24s}  {'TARGET':36s}  {'CRON':16s}  {'ENABLED':7s}  LAST_RUN",
        "-" * 110,
    ]
    for j in jobs:
        lines.append(
            f"{j.job_id:24s}  {j.target[:36]:36s}  {j.cron:16s}  "
            f"{'yes' if j.enabled else 'no':7s}  {j.last_run_ts or '(never)'}"
        )
    return "\n".join(lines)


def _run_engage_for_job(job: ScheduledJob, *, dry_run: bool, notify_drift: bool = False) -> int:
    """Spawn ``kryon engage`` with the job's params. Honest subprocess
    fork — the parent doesn't need to import the engage module."""
    cmd = [
        sys.executable,
        "-m",
        "kryon.cli._original",
        "engage",
        job.target,
        "--scope",
        job.target,
        "--client",
        "scheduled",
        "--engagement-id",
        f"{job.job_id}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}",
        "--dry-run-only",
        "--skip-reaudit",
    ]
    if notify_drift:
        cmd.append("--notify-drift")
    if job.objective:
        cmd.extend(["--objective", job.objective])
    if dry_run:
        print("[dry-run]", " ".join(cmd))
        return 0
    try:
        proc = subprocess.run(cmd, check=False, timeout=3600)
        return int(proc.returncode)
    except subprocess.TimeoutExpired:
        print(f"[scheduled] {job.job_id} timed out after 1 hour", file=sys.stderr)
        return 124


def run_schedule_command(args) -> int:
    sched = Scheduler.load()
    action = args.schedule_action

    if action == "add":
        try:
            sched.add_job(
                ScheduledJob(
                    job_id=args.id,
                    target=args.target,
                    cron=args.cron,
                    objective=args.objective,
                )
            )
        except ValueError as exc:
            print(f"add: invalid cron — {exc}", file=sys.stderr)
            return 2
        sched.save()
        print(f"added job '{args.id}' (target={args.target}, cron={args.cron})")
        return 0

    if action == "list":
        # Default rendering is the table; --json would be a future addition.
        print(_format_table(sched.jobs))
        return 0

    if action == "remove":
        removed = sched.remove_job(args.id)
        if not removed:
            print(f"remove: no such job '{args.id}'", file=sys.stderr)
            return 1
        sched.save()
        print(f"removed job '{args.id}'")
        return 0

    if action == "run-due":
        if getattr(args, "watch", False):
            return _watch_loop(args)
        return _run_due_once(sched, dry_run=args.dry_run, notify_drift=getattr(args, "notify_drift", False))

    print(f"schedule: unknown action '{action}'", file=sys.stderr)
    return 2


def _run_due_once(sched, *, dry_run: bool, notify_drift: bool) -> int:
    """Run every job whose cron matches now. Returns 1 if any job failed."""
    due = sched.due_jobs()
    if not due:
        print("(no jobs due right now)")
        return 0
    print(f"running {len(due)} due job(s)")
    any_failed = False
    for j in due:
        print(f"\n→ {j.job_id}  target={j.target}  cron={j.cron}")
        rc = _run_engage_for_job(j, dry_run=dry_run, notify_drift=notify_drift)
        if rc == 0 and not dry_run:
            sched.mark_run(j.job_id)
        elif rc != 0:
            any_failed = True
            print(f"  [warn] exit {rc}", file=sys.stderr)
    if not dry_run:
        sched.save()
    return 1 if any_failed else 0


def _watch_loop(args) -> int:
    """Q2 — Continuous monitor: re-check due jobs every --interval seconds until
    interrupted. Reloads the schedule each tick so edits are picked up live."""
    import time

    interval = max(5, int(getattr(args, "interval", 60)))
    print(f"watching schedule every {interval}s (Ctrl-C to stop)")
    try:
        while True:
            sched = Scheduler.load()
            _run_due_once(sched, dry_run=args.dry_run, notify_drift=getattr(args, "notify_drift", False))
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nstopped.")
        return 0
