"""Fase A — unified feed refresh (`kryon update`) orchestrator tests.

Each feed is best-effort and isolated: one failure never aborts the others.
Network is never touched here — the nuclei runner is injected and the
network-bound feeds are monkeypatched.
"""

from __future__ import annotations

import subprocess

from kryon.services.feed_updater import (
    DEFAULT_FEEDS,
    UpdateResult,
    run_updates,
    update_nuclei_templates,
    update_skills,
)


class _FakeProc:
    def __init__(self, returncode=0, stderr=""):
        self.returncode = returncode
        self.stderr = stderr


# --- UpdateResult ---------------------------------------------------------


def test_update_result_flags():
    assert UpdateResult("x", "ok").ok is True
    assert UpdateResult("x", "failed").ok is False
    assert UpdateResult("x", "failed").failed is True
    assert UpdateResult("x", "skipped").failed is False


# --- nuclei (runner injected, no network) ---------------------------------


def test_nuclei_ok_when_runner_returns_zero():
    r = update_nuclei_templates(runner=lambda *a, **k: _FakeProc(0))
    assert r.ok
    assert r.name == "nuclei-templates"


def test_nuclei_failed_on_nonzero_exit():
    r = update_nuclei_templates(runner=lambda *a, **k: _FakeProc(1, "network down"))
    assert r.status == "failed"
    assert "network down" in r.detail


def test_nuclei_skipped_when_binary_missing():
    def _missing(*a, **k):
        raise FileNotFoundError

    assert update_nuclei_templates(runner=_missing).status == "skipped"


def test_nuclei_failed_on_timeout():
    def _timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="nuclei", timeout=1)

    r = update_nuclei_templates(runner=_timeout, timeout=1)
    assert r.status == "failed"
    assert "timed out" in r.detail.lower()


# --- skills (no repo → skipped, no network) -------------------------------


def test_skills_skipped_without_repo():
    assert update_skills(repo_url=None).status == "skipped"
    assert update_skills(repo_url="").status == "skipped"


# --- orchestrator ---------------------------------------------------------


def test_run_updates_default_feeds_in_order(monkeypatch):
    import kryon.services.feed_updater as fu

    calls = []
    monkeypatch.setattr(
        fu, "update_nuclei_templates", lambda **k: (calls.append("nuclei"), UpdateResult("nuclei-templates", "ok"))[1]
    )
    monkeypatch.setattr(
        fu, "update_exploitdb", lambda **k: (calls.append("exploitdb"), UpdateResult("exploitdb", "ok"))[1]
    )
    monkeypatch.setattr(fu, "update_cve_cache", lambda **k: (calls.append("cve"), UpdateResult("cve-cache", "ok"))[1])

    res = fu.run_updates()
    assert [r.name for r in res] == ["nuclei-templates", "exploitdb", "cve-cache"]
    assert calls == ["nuclei", "exploitdb", "cve"]
    assert set(DEFAULT_FEEDS) == {"nuclei", "exploitdb", "cve-cache"}


def test_run_updates_isolates_failures(monkeypatch):
    import kryon.services.feed_updater as fu

    monkeypatch.setattr(fu, "update_nuclei_templates", lambda **k: UpdateResult("nuclei-templates", "failed", "x"))
    monkeypatch.setattr(fu, "update_exploitdb", lambda **k: UpdateResult("exploitdb", "ok"))
    monkeypatch.setattr(fu, "update_cve_cache", lambda **k: UpdateResult("cve-cache", "ok"))

    res = fu.run_updates(["nuclei", "exploitdb", "cve-cache"])
    assert sum(1 for r in res if r.failed) == 1
    assert sum(1 for r in res if r.ok) == 2  # the failure didn't abort the rest


def test_run_updates_unknown_feed_is_skipped():
    res = run_updates(["bogus-feed"])
    assert len(res) == 1
    assert res[0].status == "skipped"
    assert res[0].name == "bogus-feed"


def test_run_updates_selective_subset(monkeypatch):
    import kryon.services.feed_updater as fu

    monkeypatch.setattr(fu, "update_nuclei_templates", lambda **k: UpdateResult("nuclei-templates", "ok"))
    res = fu.run_updates(["nuclei"])
    assert [r.name for r in res] == ["nuclei-templates"]
