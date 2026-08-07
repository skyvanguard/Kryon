"""F144 — Pending-actions approval queue.

Any destructive action Kryon wants to run (apply a remediation,
fire an active probe, modify a config) is enqueued here first. The
operator approves explicitly via:

    kryon approve <action_id>
    kryon approve --list
    kryon approve --reject <action_id> --reason "scope issue"

For non-destructive auto-approvable actions (e.g. info-disclosure
scans), set ``KRYON_AUTO_APPROVE_LOW_RISK=true`` and they bypass the
queue. CRITICAL actions never auto-approve regardless of env.

This is a banca-safe gate: every state-changing operation must have
an audit-traceable approval before it runs against client infra.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PendingAction:
    action_id: str
    kind: str  # "remediation" | "active_probe" | "config_change" | ...
    target: str
    description: str
    command: str = ""  # the literal command/payload that will fire
    risk_level: str = RiskLevel.MEDIUM.value
    status: str = "pending"  # pending | approved | rejected | executed
    engagement_id: str = ""
    requested_at: str = ""
    decided_at: str = ""
    decided_by: str = ""
    rejection_reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _default_path() -> Path:
    root = os.environ.get("KRYON_APPROVAL_PATH", "").strip()
    if root:
        return Path(root)
    return Path(".kryon") / "approvals.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class ApprovalQueue:
    pending: list[PendingAction] = field(default_factory=list)
    state_path: Path = field(default_factory=_default_path)

    @classmethod
    def load(cls, path: Path | None = None) -> ApprovalQueue:
        p = path or _default_path()
        if not p.exists():
            return cls(pending=[], state_path=p)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return cls(pending=[], state_path=p)
        items = [PendingAction(**a) for a in data.get("pending", []) if isinstance(a, dict)]
        return cls(pending=items, state_path=p)

    def save(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(
                json.dumps({"pending": [a.to_dict() for a in self.pending]}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("approval queue save failed: %s", exc)

    def request(
        self,
        *,
        kind: str,
        target: str,
        description: str,
        command: str = "",
        risk_level: str = RiskLevel.MEDIUM.value,
        engagement_id: str = "",
        action_id: str | None = None,
    ) -> tuple[PendingAction, bool]:
        """Enqueue a pending action. Returns ``(action, auto_approved)``.

        When ``risk_level in {low, medium}`` AND
        ``KRYON_AUTO_APPROVE_LOW_RISK=true``, the action is auto-approved
        in place and the second tuple element is True. CRITICAL/HIGH
        actions always require explicit approval."""
        rl = RiskLevel(risk_level) if risk_level in {r.value for r in RiskLevel} else RiskLevel.MEDIUM
        action = PendingAction(
            action_id=action_id or uuid.uuid4().hex[:12],
            kind=kind,
            target=target,
            description=description,
            command=command,
            risk_level=rl.value,
            engagement_id=engagement_id,
            requested_at=_now_iso(),
        )
        auto = False
        if _env_true("KRYON_AUTO_APPROVE_LOW_RISK") and rl in {RiskLevel.LOW, RiskLevel.MEDIUM}:
            action.status = "approved"
            action.decided_at = _now_iso()
            action.decided_by = "auto"
            auto = True
        self.pending.append(action)
        return action, auto

    def list(self, *, status: str | None = None) -> list[PendingAction]:
        if status is None:
            return list(self.pending)
        return [a for a in self.pending if a.status == status]

    def get(self, action_id: str) -> PendingAction | None:
        return next((a for a in self.pending if a.action_id == action_id), None)

    def approve(self, action_id: str, *, decided_by: str = "operator") -> bool:
        for a in self.pending:
            if a.action_id == action_id and a.status == "pending":
                a.status = "approved"
                a.decided_at = _now_iso()
                a.decided_by = decided_by
                return True
        return False

    def reject(self, action_id: str, *, reason: str = "", decided_by: str = "operator") -> bool:
        for a in self.pending:
            if a.action_id == action_id and a.status == "pending":
                a.status = "rejected"
                a.decided_at = _now_iso()
                a.decided_by = decided_by
                a.rejection_reason = reason
                return True
        return False

    def mark_executed(self, action_id: str) -> bool:
        for a in self.pending:
            if a.action_id == action_id and a.status == "approved":
                a.status = "executed"
                return True
        return False

    def is_approved(self, action_id: str) -> bool:
        a = self.get(action_id)
        return a is not None and a.status in {"approved", "executed"}
