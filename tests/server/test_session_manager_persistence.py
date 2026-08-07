"""Direct SessionManager persistence tests (no FastAPI TestClient — that hangs on
the app lifespan). Covers the bounded-disk invariants of the #2 persistence layer:
eviction must drop the on-disk snapshot, and startup load must cap + prune."""

from __future__ import annotations

import json

import kryon.server.sessions as sessions_mod
from kryon.server.sessions import SessionManager


class _FakeModel:
    def __init__(self):
        self.message_history: list = []


class _FakeAgent:
    def __init__(self, model_override=None):
        self.model = _FakeModel()
        self.model_override = model_override


def _files(d):
    return sorted(p.name for p in d.glob("*.json"))


def test_eviction_deletes_disk_file(tmp_path, monkeypatch):
    """At capacity, the evicted-from-memory session's JSON must also leave disk —
    else evicted sessions linger and reload on every restart (unbounded growth)."""
    monkeypatch.setattr(sessions_mod, "_MAX_SESSIONS", 3)
    sm = SessionManager(persist_dir=tmp_path)

    created = [sm.create_session("kryon", _FakeAgent()) for _ in range(4)]

    # memory holds exactly the cap; the oldest was evicted
    assert len(sm.list_sessions()) == 3
    oldest = created[0]
    assert oldest.session_id not in {s.session_id for s in sm.list_sessions()}
    # and its disk snapshot is gone (disk stays bounded, mirrors memory)
    assert not (tmp_path / f"{oldest.session_id}.json").exists()
    assert len(_files(tmp_path)) == 3


def test_load_caps_and_prunes(tmp_path, monkeypatch):
    """Startup must load only the newest _MAX_SESSIONS and prune older files, so a
    dir with thousands of stale snapshots doesn't bloat memory / slow startup."""
    monkeypatch.setattr(sessions_mod, "_MAX_SESSIONS", 2)
    # Seed 5 snapshots directly on disk with increasing mtime (oldest → newest).
    for i in range(5):
        p = tmp_path / f"sess{i}.json"
        p.write_text(
            json.dumps({"session_id": f"sess{i}", "agent_key": "kryon", "input_history": []}),
            encoding="utf-8",
        )
        # bump mtime so ordering is deterministic (no Date.now reliance)
        import os

        os.utime(p, (1000 + i, 1000 + i))

    sm = SessionManager(persist_dir=tmp_path)

    loaded = {s.session_id for s in sm.list_sessions()}
    assert loaded == {"sess3", "sess4"}  # the two newest
    # the older three were pruned from disk
    assert _files(tmp_path) == ["sess3.json", "sess4.json"]


def test_load_oldest_first_so_eviction_drops_true_oldest(tmp_path, monkeypatch):
    """Loaded oldest-first → dict order reflects age → a subsequent create evicts the
    genuinely-oldest, not an arbitrary one."""
    monkeypatch.setattr(sessions_mod, "_MAX_SESSIONS", 2)
    import os

    for i in range(2):
        p = tmp_path / f"old{i}.json"
        p.write_text(
            json.dumps({"session_id": f"old{i}", "agent_key": "kryon", "input_history": []}),
            encoding="utf-8",
        )
        os.utime(p, (2000 + i, 2000 + i))

    sm = SessionManager(persist_dir=tmp_path)
    # at cap (2); creating one more evicts old0 (oldest), keeps old1
    sm.create_session("kryon", _FakeAgent())
    remaining = {s.session_id for s in sm.list_sessions()}
    assert "old0" not in remaining
    assert "old1" in remaining


def test_delete_session_still_removes_file(tmp_path):
    sm = SessionManager(persist_dir=tmp_path)
    s = sm.create_session("kryon", _FakeAgent())
    assert (tmp_path / f"{s.session_id}.json").exists()

    assert sm.delete_session(s.session_id) is True
    assert not (tmp_path / f"{s.session_id}.json").exists()
