"""Regression tests for the Tier-3 CLI/REPL fixes (3rd bug hunt):
- EngagementQueue claim must be atomic so two `queue process` workers can't double-run.
- draft read/delete/promote must reject path-traversal names.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from kryon.queue.queue import EngagementQueue


def test_claim_atomic_only_one_worker_wins():
    d = Path(tempfile.mkdtemp()) / "q.json"
    seed = EngagementQueue.load(d)
    seed.add(target="10.0.0.1", objective="audit")
    seed.save()

    # Two independent in-memory snapshots = two concurrent `queue process` workers.
    q1 = EngagementQueue.load(d)
    q2 = EngagementQueue.load(d)
    iid = q1.items[0].item_id

    r1 = q1.claim_atomic(iid)
    r2 = q2.claim_atomic(iid)
    assert r1 != r2  # exactly one wins
    assert r1 is True and r2 is False

    # A third worker also loses (item is 'running' on disk).
    assert EngagementQueue.load(d).claim_atomic(iid) is False


def test_finish_atomic_persists_status():
    d = Path(tempfile.mkdtemp()) / "q.json"
    q = EngagementQueue.load(d)
    q.add(target="t", objective="o")
    q.save()
    iid = q.items[0].item_id
    q.claim_atomic(iid)
    q.finish_atomic(iid, ok=True)
    # Re-read from disk: status persisted.
    assert EngagementQueue.load(d).items[0].status == "completed"


def test_draft_name_rejects_traversal():
    from kryon.learning.draft_writer import _draft_path, delete_draft, read_draft

    assert _draft_path("../../../etc/passwd") is None
    assert _draft_path("a/b") is None
    assert _draft_path("..") is None
    assert _draft_path(".hidden") is None
    assert _draft_path("clean-name") is not None
    assert read_draft("../../etc/passwd") is None
    assert delete_draft("../../etc/passwd") is False
