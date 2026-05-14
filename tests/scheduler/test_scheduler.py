"""F135 — Scheduler tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from kryon.scheduler import ScheduledJob, Scheduler, parse_simple_cron
from kryon.scheduler.scheduler import cron_matches

# ---------------------------------------------------------------------------
# parse_simple_cron
# ---------------------------------------------------------------------------


def test_parse_all_stars():
    minute, hour, dom, month, dow = parse_simple_cron("* * * * *")
    assert minute is None and hour is None and dom is None and month is None and dow is None


def test_parse_specific_minute():
    minute, *_ = parse_simple_cron("0 * * * *")
    assert minute == {0}


def test_parse_list_of_minutes():
    minute, *_ = parse_simple_cron("0,15,30,45 * * * *")
    assert minute == {0, 15, 30, 45}


def test_parse_rejects_wrong_field_count():
    with pytest.raises(ValueError):
        parse_simple_cron("0 6 * *")  # only 4 fields


def test_parse_rejects_ranges():
    with pytest.raises(ValueError):
        parse_simple_cron("0 6-8 * * *")


def test_parse_rejects_steps():
    with pytest.raises(ValueError):
        parse_simple_cron("*/5 * * * *")


# ---------------------------------------------------------------------------
# cron_matches
# ---------------------------------------------------------------------------


def test_match_every_minute():
    dt = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    assert cron_matches("* * * * *", dt)


def test_match_specific_hour():
    dt = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    assert cron_matches("0 6 * * *", dt)
    assert not cron_matches("0 7 * * *", dt)


def test_match_specific_day_of_month():
    dt = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    assert cron_matches("0 6 14 * *", dt)
    assert not cron_matches("0 6 15 * *", dt)


def test_match_day_of_week():
    # 2026-05-14 is a Thursday. Cron weekday Sunday=0..Saturday=6,
    # so Thursday=4.
    dt = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    assert cron_matches("0 6 * * 4", dt)
    assert not cron_matches("0 6 * * 0", dt)


# ---------------------------------------------------------------------------
# Scheduler persistence + CRUD
# ---------------------------------------------------------------------------


def test_load_missing_returns_empty(tmp_path):
    sched = Scheduler.load(tmp_path / "no.json")
    assert sched.jobs == []


def test_add_then_save_then_load_roundtrip(tmp_path):
    path = tmp_path / "schedule.json"
    sched = Scheduler.load(path)
    sched.add_job(ScheduledJob(job_id="j1", target="x.com", cron="0 6 * * *", objective="recon"))
    sched.save()
    re = Scheduler.load(path)
    assert len(re.jobs) == 1
    assert re.jobs[0].job_id == "j1"


def test_add_replaces_existing_job_id(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(ScheduledJob(job_id="j1", target="x.com", cron="0 6 * * *"))
    sched.add_job(ScheduledJob(job_id="j1", target="x.com", cron="0 7 * * *"))
    assert len(sched.jobs) == 1
    assert sched.jobs[0].cron == "0 7 * * *"


def test_add_rejects_bad_cron(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    with pytest.raises(ValueError):
        sched.add_job(ScheduledJob(job_id="j", target="x", cron="not-cron"))


def test_remove_job(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(ScheduledJob(job_id="j1", target="x", cron="* * * * *"))
    assert sched.remove_job("j1") is True
    assert sched.jobs == []
    assert sched.remove_job("not-there") is False


# ---------------------------------------------------------------------------
# due_jobs
# ---------------------------------------------------------------------------


def test_due_returns_jobs_matching_cron(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(ScheduledJob(job_id="every-minute", target="x", cron="* * * * *"))
    sched.add_job(ScheduledJob(job_id="six-am", target="x", cron="0 6 * * *"))
    now = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    due_ids = {j.job_id for j in sched.due_jobs(now=now)}
    assert "every-minute" in due_ids
    assert "six-am" in due_ids


def test_due_skips_disabled_jobs(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(ScheduledJob(job_id="off", target="x", cron="* * * * *", enabled=False))
    now = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    assert sched.due_jobs(now=now) == []


def test_due_skips_if_last_run_same_minute(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(
        ScheduledJob(
            job_id="j",
            target="x",
            cron="* * * * *",
            last_run_ts="2026-05-14T06:00:30Z",
        )
    )
    # Same minute as last_run → not due.
    now = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    assert sched.due_jobs(now=now) == []
    # Next minute → due.
    now2 = datetime(2026, 5, 14, 6, 1, tzinfo=timezone.utc)
    assert len(sched.due_jobs(now=now2)) == 1


def test_mark_run_updates_last_run(tmp_path):
    sched = Scheduler.load(tmp_path / "x.json")
    sched.add_job(ScheduledJob(job_id="j", target="x", cron="* * * * *"))
    when = datetime(2026, 5, 14, 6, 0, tzinfo=timezone.utc)
    sched.mark_run("j", when=when)
    assert sched.jobs[0].last_run_ts == "2026-05-14T06:00:00Z"
