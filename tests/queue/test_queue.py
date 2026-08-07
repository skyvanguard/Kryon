"""F143 — Queue tests."""

from __future__ import annotations

from kryon.queue import EngagementQueue, QueueItem


def test_load_missing_returns_empty(tmp_path):
    q = EngagementQueue.load(tmp_path / "no.json")
    assert q.items == []


def test_add_and_save_roundtrip(tmp_path):
    path = tmp_path / "q.json"
    q = EngagementQueue.load(path)
    q.add("x.com", objective="audit")
    q.save()
    q2 = EngagementQueue.load(path)
    assert len(q2.items) == 1
    assert q2.items[0].target == "x.com"


def test_add_dedupes_pending_with_same_target_and_objective(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    first = q.add("x.com", objective="audit")
    second = q.add("x.com", objective="audit")
    assert first.item_id == second.item_id
    assert len(q.items) == 1


def test_add_does_not_dedupe_when_disabled(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    q.add("x.com", objective="audit", dedupe=False)
    q.add("x.com", objective="audit", dedupe=False)
    assert len(q.items) == 2


def test_add_does_not_dedupe_different_objectives(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    q.add("x.com", objective="audit PCI-DSS")
    q.add("x.com", objective="find RCE")
    assert len(q.items) == 2


def test_next_due_picks_highest_priority(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    q.add("low.com", priority=80)
    q.add("high.com", priority=10)
    q.add("medium.com", priority=50)
    nxt = q.next_due()
    assert nxt.target == "high.com"


def test_next_due_skips_running_items(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    a = q.add("a.com", priority=10)
    b = q.add("b.com", priority=20)
    q.mark_started(a.item_id)
    nxt = q.next_due()
    assert nxt.item_id == b.item_id


def test_next_due_empty_returns_none(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    assert q.next_due() is None


def test_mark_started_updates_status(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    item = q.add("x.com")
    assert q.mark_started(item.item_id) is True
    found = next(i for i in q.items if i.item_id == item.item_id)
    assert found.status == "running"
    assert found.started_at


def test_mark_finished_ok(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    item = q.add("x.com")
    q.mark_started(item.item_id)
    q.mark_finished(item.item_id, ok=True)
    found = next(i for i in q.items if i.item_id == item.item_id)
    assert found.status == "completed"


def test_mark_finished_failure_records_error(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    item = q.add("x.com")
    q.mark_started(item.item_id)
    q.mark_finished(item.item_id, ok=False, error="timeout")
    found = next(i for i in q.items if i.item_id == item.item_id)
    assert found.status == "failed"
    assert found.error == "timeout"


def test_mark_unknown_id_returns_false(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    assert q.mark_started("no-such-id") is False
    assert q.mark_finished("no-such-id", ok=True) is False


def test_remove(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    item = q.add("x.com")
    assert q.remove(item.item_id) is True
    assert q.items == []
    assert q.remove("not-there") is False


def test_list_filter_by_status(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    a = q.add("a.com")
    b = q.add("b.com")
    q.mark_started(a.item_id)
    pending = q.list(status="pending")
    running = q.list(status="running")
    assert len(pending) == 1 and pending[0].item_id == b.item_id
    assert len(running) == 1 and running[0].item_id == a.item_id


def test_purge_completed(tmp_path):
    q = EngagementQueue.load(tmp_path / "q.json")
    a = q.add("a.com")
    b = q.add("b.com")
    c = q.add("c.com")
    q.mark_started(a.item_id)
    q.mark_finished(a.item_id, ok=True)
    q.mark_started(b.item_id)
    q.mark_finished(b.item_id, ok=False, error="x")
    purged = q.purge_completed()
    assert purged == 2
    assert [i.target for i in q.items] == ["c.com"]
