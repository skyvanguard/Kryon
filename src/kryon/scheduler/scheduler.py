"""F135 — Engagement scheduling subsystem.

Stores per-target scheduled jobs in ``.kryon/schedule.json`` and lets
an operator (or a cron-on-cron daemon) ask "which jobs are due now?".

Cron support is a practical subset of the standard 5-field syntax — we
parse ``minute hour day_of_month month day_of_week`` with ``*``, explicit
integer lists (``0,30``), ranges (``1-5``), and steps (``*/15``,
``0-30/10``). No named aliases (``@daily``, ``MON``). The point is not to
compete with apscheduler — it's to let Kryon track schedules without
adding a heavyweight dep. Operators who need full cron should schedule
``kryon engage`` from OS cron / systemd timer directly; this module is for
in-process scheduling and for showing operators what's due via
``kryon schedule list``.

Usage:

    sched = Scheduler.load()
    sched.add_job(ScheduledJob(
        job_id="example-daily",
        target="www.example.com",
        cron="0 6 * * *",  # 06:00 UTC daily
        objective="audit attack surface",
    ))
    sched.save()
    due = sched.due_jobs(now=datetime.now(timezone.utc))
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from kryon.util.atomic_state import read_json_locked, write_json_atomic

logger = logging.getLogger(__name__)

# Accepts: *  |  */N  |  a  |  a-b  |  a-b/N  and comma-joined lists thereof.
_CRON_TOKEN = r"(?:\*|\d+(?:-\d+)?)(?:/\d+)?"
_CRON_FIELD_RE = re.compile(rf"^{_CRON_TOKEN}(?:,{_CRON_TOKEN})*$")

# (min, max) inclusive bounds per field: minute, hour, dom, month, dow.
_FIELD_BOUNDS: tuple[tuple[int, int], ...] = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 6))


@dataclass
class ScheduledJob:
    """One target's cron schedule.

    ``kind`` selects the child command: ``engage`` (single host/URL, the
    default) or ``sweep`` (a CIDR/range → ``kryon sweep``, for an entire
    segment). ``framework``/``client`` thread compliance context to the
    child; ``dry_run_only`` keeps scheduled runs read-only/passive by
    default (banca-safe) while letting an operator opt into remediation.
    """

    job_id: str
    target: str
    cron: str  # 5-field minute hour dom month dow
    objective: str = ""
    last_run_ts: str | None = None
    enabled: bool = True
    kind: str = "engage"  # "engage" | "sweep" | "update" (feed refresh)
    framework: str = ""
    client: str = "scheduled"
    dry_run_only: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_field(field_value: str, lo: int, hi: int) -> set[int] | None:
    """Parse one cron field into a set of allowed ints, or None for ``*``
    (matches every value). Supports lists, ranges, and steps.

    Raises ``ValueError`` on out-of-bounds values, inverted ranges, or a
    non-positive step — fail loud so the operator gets a clear error
    instead of a silently wrong schedule.
    """
    if field_value == "*":
        return None
    result: set[int] = set()
    for token in field_value.split(","):
        base, _, step_s = token.partition("/")
        step = int(step_s) if step_s else 1
        if step <= 0:
            raise ValueError(f"cron step must be positive: '{token}'")
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            a, b = base.split("-", 1)
            start, end = int(a), int(b)
        else:
            start = end = int(base)
        if start < lo or end > hi or start > end:
            raise ValueError(f"cron field value out of range [{lo}-{hi}] or inverted: '{token}'")
        result.update(range(start, end + 1, step))
    return result or None


def parse_simple_cron(
    expr: str,
) -> tuple[set[int] | None, set[int] | None, set[int] | None, set[int] | None, set[int] | None]:
    """Parse a 5-field cron expression. ``*`` is encoded as None to
    indicate "every value of this field"; lists/ranges/steps become sets.

    Raises ``ValueError`` on unsupported syntax (named aliases) or values
    outside each field's valid range.
    """
    parts = (expr or "").split()
    if len(parts) != 5:
        raise ValueError(f"cron expression must have 5 fields, got {len(parts)}: '{expr}'")
    parsed: list[set[int] | None] = []
    for field_value, (lo, hi) in zip(parts, _FIELD_BOUNDS):
        if not _CRON_FIELD_RE.match(field_value):
            raise ValueError(f"unsupported cron field syntax: '{field_value}'")
        parsed.append(_parse_field(field_value, lo, hi))
    return parsed[0], parsed[1], parsed[2], parsed[3], parsed[4]


def _matches(value: int, allowed: set[int] | None) -> bool:
    return allowed is None or value in allowed


def cron_matches(expr: str, dt: datetime) -> bool:
    """True iff ``dt`` matches the cron expression. The seconds field
    is ignored — cron has 1-minute resolution."""
    minute, hour, dom, month, dow = parse_simple_cron(expr)
    # Python's weekday: Monday=0, Sunday=6. Cron: Sunday=0..Saturday=6.
    cron_dow = (dt.weekday() + 1) % 7
    return (
        _matches(dt.minute, minute)
        and _matches(dt.hour, hour)
        and _matches(dt.day, dom)
        and _matches(dt.month, month)
        and _matches(cron_dow, dow)
    )


def _default_state_path() -> Path:
    root = os.environ.get("KRYON_SCHEDULE_PATH", "").strip()
    if root:
        return Path(root)
    return Path(".kryon") / "schedule.json"


@dataclass
class Scheduler:
    """Persisted collection of scheduled jobs."""

    jobs: list[ScheduledJob] = field(default_factory=list)
    state_path: Path = field(default_factory=_default_state_path)

    @classmethod
    def load(cls, path: Path | None = None) -> Scheduler:
        p = path or _default_state_path()
        data = read_json_locked(p, default={"jobs": []})
        jobs = [ScheduledJob(**j) for j in data.get("jobs", []) if isinstance(j, dict)]
        return cls(jobs=jobs, state_path=p)

    def save(self) -> None:
        write_json_atomic(self.state_path, {"jobs": [j.to_dict() for j in self.jobs]})

    def add_job(self, job: ScheduledJob) -> None:
        """Add or replace a job by ``job_id``."""
        # Validate the cron eagerly so the operator gets the error now,
        # not at first fire.
        parse_simple_cron(job.cron)
        self.jobs = [j for j in self.jobs if j.job_id != job.job_id]
        self.jobs.append(job)

    def remove_job(self, job_id: str) -> bool:
        before = len(self.jobs)
        self.jobs = [j for j in self.jobs if j.job_id != job_id]
        return len(self.jobs) < before

    def get_job(self, job_id: str) -> ScheduledJob | None:
        return next((j for j in self.jobs if j.job_id == job_id), None)

    def due_jobs(self, *, now: datetime | None = None) -> list[ScheduledJob]:
        """Return jobs whose cron matches ``now`` (default: utcnow) AND
        weren't already run at the same minute. ``enabled=False`` jobs
        are skipped."""
        when = now or datetime.now(timezone.utc)
        due: list[ScheduledJob] = []
        for j in self.jobs:
            if not j.enabled:
                continue
            try:
                if not cron_matches(j.cron, when):
                    continue
            except ValueError:
                continue
            # Avoid double-running within the same minute.
            if j.last_run_ts:
                try:
                    ts = j.last_run_ts.replace("Z", "+00:00")
                    last = datetime.fromisoformat(ts)
                    if last.tzinfo is None:
                        last = last.replace(tzinfo=timezone.utc)
                    if last.replace(second=0, microsecond=0) == when.replace(second=0, microsecond=0):
                        continue
                except (ValueError, TypeError):
                    pass
            due.append(j)
        return due

    def mark_run(self, job_id: str, *, when: datetime | None = None) -> None:
        when = when or datetime.now(timezone.utc)
        import dataclasses

        for idx, j in enumerate(self.jobs):
            if j.job_id == job_id:
                # dataclasses.replace preserves every field (kind/framework/
                # client/dry_run_only) — a manual reconstruction would silently
                # drop the ones it forgets to list.
                self.jobs[idx] = dataclasses.replace(
                    j,
                    last_run_ts=when.isoformat(timespec="seconds").replace("+00:00", "Z"),
                )
                return
