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

import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

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
        if not p.exists():
            return cls(items=[], state_path=p)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("queue load failed (%s) — starting empty", exc)
            return cls(items=[], state_path=p)
        items = [QueueItem(**i) for i in data.get("items", []) if isinstance(i, dict)]
        return cls(items=items, state_path=p)

    def save(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(
                json.dumps({"items": [i.to_dict() for i in self.items]}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("queue save failed: %s", exc)

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

    def mark_finished(self, item_id: str, *, ok: bool, error: str = "") -> bool:
        for i in self.items:
            if i.item_id == item_id:
                i.status = "completed" if ok else "failed"
                i.finished_at = _now_iso()
                if error:
                    i.error = error
                return True
        return False

    def remove(self, item_id: str) -> bool:
        before = len(self.items)
        self.items = [i for i in self.items if i.item_id != item_id]
        return len(self.items) < before

    def purge_completed(self) -> int:
        before = len(self.items)
        self.items = [i for i in self.items if i.status not in {"completed", "failed"}]
        return before - len(self.items)
