"""feed_updater OpenVAS hook — update_openvas_feed + run_updates dispatch.
The greenbone-feed-sync call is an injected runner; no binary needed."""

from __future__ import annotations

import subprocess
import types

from kryon.services import feed_updater
from kryon.services.feed_updater import ALL_FEEDS, run_updates, update_openvas_feed


def _proc(returncode: int, stderr: str = ""):
    def runner(*_args, **_kwargs):
        return types.SimpleNamespace(returncode=returncode, stderr=stderr)

    return runner


def test_openvas_feed_ok():
    r = update_openvas_feed(runner=_proc(0))
    assert r.name == "openvas-feed"
    assert r.status == "ok"


def test_openvas_feed_failed():
    r = update_openvas_feed(runner=_proc(1, "boom"))
    assert r.status == "failed"
    assert "boom" in r.detail


def test_openvas_feed_skipped_when_binary_absent():
    def runner(*_a, **_k):
        raise FileNotFoundError("greenbone-feed-sync")

    r = update_openvas_feed(runner=runner)
    assert r.status == "skipped"


def test_openvas_feed_timeout():
    def runner(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="greenbone-feed-sync", timeout=1)

    r = update_openvas_feed(runner=runner)
    assert r.status == "failed"
    assert "timed out" in r.detail


def test_run_updates_dispatches_openvas():
    results = run_updates(["openvas"], openvas_runner=_proc(0))
    assert len(results) == 1
    assert results[0].name == "openvas-feed"
    assert results[0].status == "ok"


def test_openvas_is_opt_in_only():
    # In ALL_FEEDS (via --all) but NOT a default feed (sync is heavy/slow).
    assert "openvas" in ALL_FEEDS
    assert "openvas" not in feed_updater.DEFAULT_FEEDS
