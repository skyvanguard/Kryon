"""feed_updater Cinc profiles hook — update_cinc_profiles + run_updates dispatch."""

from __future__ import annotations

import types

from kryon.services import feed_updater
from kryon.services.feed_updater import ALL_FEEDS, UpdateResult, run_updates, update_cinc_profiles


def _proc(returncode: int):
    def runner(*_a, **_k):
        return types.SimpleNamespace(returncode=returncode, stdout="", stderr="")

    return runner


def test_cinc_profiles_ok(tmp_path):
    r = update_cinc_profiles(
        profiles=["https://github.com/dev-sec/ssh-baseline"],
        cache_dir=str(tmp_path),
        runner=_proc(0),
    )
    assert r.name == "cinc-profiles"
    assert r.status == "ok"
    assert "1 cached" in r.detail


def test_cinc_profiles_skipped_no_git_urls(tmp_path):
    r = update_cinc_profiles(profiles=["/local/only/path"], cache_dir=str(tmp_path), runner=_proc(0))
    assert r.status == "skipped"


def test_cinc_profiles_failed(tmp_path):
    r = update_cinc_profiles(
        profiles=["https://github.com/dev-sec/ssh-baseline"],
        cache_dir=str(tmp_path),
        runner=_proc(1),
    )
    assert r.status == "failed"


def test_run_updates_dispatches_cinc(monkeypatch):
    monkeypatch.setattr(feed_updater, "update_cinc_profiles", lambda **_kw: UpdateResult("cinc-profiles", "ok", "stub"))
    results = run_updates(["cinc"])
    assert len(results) == 1
    assert results[0].name == "cinc-profiles"


def test_cinc_is_opt_in_only():
    assert "cinc" in ALL_FEEDS
    assert "cinc" not in feed_updater.DEFAULT_FEEDS
