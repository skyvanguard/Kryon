"""F143 — Multi-target engagement queue.

Persists a FIFO/priority queue of pending engagements in
``.kryon/queue.json`` so multiple targets can be processed without
re-running discovery / scheduling logic per target. ``kryon queue
process`` drains the queue with a worker pool (concurrency limit).

Each queue item carries:
  - target, objective (passed to ``kryon engage``)
  - priority (lower number = run earlier)
  - status: pending / running / completed / failed
  - timestamps for telemetry

Concurrency: workers claim items by setting status=running. Items
stay claimed across a worker crash (no automatic unclaim) so the
operator can inspect and re-queue manually. This is intentional
banca-safe behaviour: silent retries can fire duplicate destructive
actions.
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from kryon.util.atomic_state import read_json_locked, write_json_atomic

logger = logging.getLogger(__name__)


@dataclass
class QueueItem:
    item_id: str
    target: str
    objective: str = ""
    priority: int = 50  # lower = earlier
    status: str = "pending"  # pending | running | completed | failed
    queued_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _default_queue_path() -> Path:
    root = os.environ.get("KRYON_QUEUE_PATH", "").strip()
    if root:
        return Path(root)
    return Path(".kryon") / "queue.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class EngagementQueue:
    items: list[QueueItem] = field(default_factory=list)
    state_path: Path = field(default_factory=_default_queue_path)

    @classmethod
    def load(cls, path: Path | None = None) -> EngagementQueue:
        p = path or _default_queue_path()
        data = read_json_locked(p, default={"items": []})
        items = [QueueItem(**i) for i in data.get("items", []) if isinstance(i, dict)]
        return cls(items=items, state_path=p)

    def save(self) -> None:
        write_json_atomic(self.state_path, {"items": [i.to_dict() for i in self.items]})

    def add(
        self,
        target: str,
        *,
        objective: str = "",
        priority: int = 50,
        item_id: str | None = None,
        dedupe: bool = True,
    ) -> QueueItem:
        """Append an item. Returns the new item. When ``dedupe=True``
        (default) and the same target+objective is already pending,
        return the existing item instead of creating a duplicate."""
        if dedupe:
            for existing in self.items:
                if existing.status == "pending" and existing.target == target and existing.objective == objective:
                    return existing
        item = QueueItem(
            item_id=item_id or uuid.uuid4().hex[:12],
            target=target,
            objective=objective,
            priority=priority,
            queued_at=_now_iso(),
        )
        self.items.append(item)
        return item

    def list(self, *, status: str | None = None) -> list[QueueItem]:
        if status is None:
            return list(self.items)
        return [i for i in self.items if i.status == status]

    def next_due(self) -> QueueItem | None:
        """Return the highest-priority pending item (lowest priority
        number wins, ties broken by queued_at)."""
        pending = [i for i in self.items if i.status == "pending"]
        if not pending:
            return None
        pending.sort(key=lambda x: (x.priority, x.queued_at))
        return pending[0]

    def mark_started(self, item_id: str) -> bool:
        for i in self.items:
            if i.item_id == item_id:
                i.status = "running"
                i.started_at = _now_iso()
                return True
        return False

    def claim_atomic(self, item_id: str) -> bool:
        """Atomically claim a pending item for execution. Under the state lock, re-reads
        the ON-DISK queue and only transitions the item to 'running' if it is still
        'pending' there — returning True iff THIS caller won the claim. This is what makes
        `queue process` safe against two concurrent workers double-running the same
        engagement (mark_started+save on a stale in-memory snapshot did not)."""
        from kryon.util.atomic_state import update_json_locked

        def _mutate(data):
            items = data.get("items", []) if isinstance(data, dict) else []
            for d in items:
                if d.get("item_id") == item_id:
                    if d.get("status") != "pending":
                        return None, False  # already claimed by another worker — no write
                    d["status"] = "running"
                    d["started_at"] = _now_iso()
                    return {"items": items}, True
            return None, False

        won = update_json_locked(self.state_path, _mutate, default={"items": []})
        if won:
            for i in self.items:  # keep the in-memory snapshot consistent
                if i.item_id == item_id:
                    i.status = "running"
                    i.started_at = _now_iso()
        return bool(won)

    def mark_finished(self, item_id: str, *, ok: bool, error: str = "") -> bool:
        for i in self.items:
            if i.item_id == item_id:
                i.status = "completed" if ok else "failed"
                i.finished_at = _now_iso()
                if error:
                    i.error = error
                return True
        return False

    def finish_atomic(self, item_id: str, *, ok: bool, error: str = "") -> bool:
        """Atomically transition ONE item to completed/failed on disk (read-modify-write
        under the state lock), instead of mark_finished + save() which rewrote the whole
        in-memory snapshot and could clobber another worker's concurrent claims."""
        from kryon.util.atomic_state import update_json_locked

        status = "completed" if ok else "failed"

        def _mutate(data):
            items = data.get("items", []) if isinstance(data, dict) else []
            for d in items:
                if d.get("item_id") == item_id:
                    d["status"] = status
                    d["finished_at"] = _now_iso()
                    if error:
                        d["error"] = error
                    return {"items": items}, True
            return None, False

        update_json_locked(self.state_path, _mutate, default={"items": []})
        return self.mark_finished(item_id, ok=ok, error=error)  # sync in-memory

    def remove(self, item_id: str) -> bool:
        before = len(self.items)
        self.items = [i for i in self.items if i.item_id != item_id]
        return len(self.items) < before

    def purge_completed(self) -> int:
        before = len(self.items)
        self.items = [i for i in self.items if i.status not in {"completed", "failed"}]
        return before - len(self.items)
