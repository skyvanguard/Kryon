"""F136 — Engagement checkpoint + resume.

After each completed phase the orchestrator writes the engagement
state to ``.kryon/checkpoints/<engagement_id>.json``. If the process
crashes mid-engagement (OOM, container restart, network blip during
an LLM call), ``kryon engage --resume <engagement_id>`` rebuilds the
plan from the checkpoint and starts at the first PENDING phase
instead of re-running the work that already produced findings.

The checkpoint is intentionally narrow:

  - ``engagement_id`` + ``target`` + ``scope`` — re-derive the run.
  - ``families`` — what Phase 1 nmap detected.
  - ``plan_phases`` — every phase + its status (so we know what's
    completed/skipped/failed/pending).
  - ``findings`` + ``new_findings`` — every finding accumulated so
    far. The resume path uses these as the seed list and continues
    appending.
  - ``goal`` — the declared --objective serialized.
  - ``verdict_info`` — the last computed verdict (None if no goal).

Findings are stored as plain dicts so the checkpoint is robust to
Finding dataclass changes between releases. ``confidence`` and
``needs_verification`` round-trip when present.

Pure module: read / write to disk only via the explicit functions.
No global state.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CheckpointPhase:
    """Subset of PlanPhase serialised in the checkpoint."""

    name: str
    status: str  # "pending" / "running" / "completed" / "skipped" / "failed"
    agent_key: str
    max_turns: int
    depends_on: list[str] = field(default_factory=list)
    goal_kind_hint: str | None = None


@dataclass
class Checkpoint:
    """Frozen engagement state for resume."""

    engagement_id: str
    target: str
    scope: str
    families: list[str]
    plan_phases: list[CheckpointPhase]
    findings: list[dict[str, Any]]
    new_findings: list[dict[str, Any]]
    goal: dict[str, Any] | None
    verdict_info: dict[str, Any] | None
    saved_at: str
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Checkpoint:
        phases = [CheckpointPhase(**p) for p in data.get("plan_phases", []) if isinstance(p, dict)]
        return cls(
            engagement_id=str(data.get("engagement_id", "")),
            target=str(data.get("target", "")),
            scope=str(data.get("scope", "")),
            families=list(data.get("families", []) or []),
            plan_phases=phases,
            findings=list(data.get("findings", []) or []),
            new_findings=list(data.get("new_findings", []) or []),
            goal=data.get("goal"),
            verdict_info=data.get("verdict_info"),
            saved_at=str(data.get("saved_at", "")),
            schema_version=int(data.get("schema_version", 1)),
        )

    def first_pending_phase_index(self) -> int | None:
        """Return the index of the first phase still PENDING, or None
        when every phase is decided."""
        for i, p in enumerate(self.plan_phases):
            if p.status == "pending":
                return i
        return None


def _default_dir() -> Path:
    root = os.environ.get("KRYON_CHECKPOINT_PATH", "").strip()
    if root:
        return Path(root)
    return Path(".kryon") / "checkpoints"


def checkpoint_path(engagement_id: str, *, base: Path | None = None) -> Path:
    return (base or _default_dir()) / f"{engagement_id}.json"


def save_checkpoint(checkpoint: Checkpoint, *, base: Path | None = None) -> Path | None:
    """Persist a checkpoint. Returns the path written or None on
    failure (never raises — a forensic write must not abort the run)."""
    p = checkpoint_path(checkpoint.engagement_id, base=base)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(checkpoint.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return p
    except OSError as exc:
        logger.warning("checkpoint save failed: %s", exc)
        return None


def load_checkpoint(engagement_id: str, *, base: Path | None = None) -> Checkpoint | None:
    """Read a checkpoint by ``engagement_id``. Returns ``None`` if the
    file is missing or malformed."""
    p = checkpoint_path(engagement_id, base=base)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("checkpoint load %s failed (%s)", p, exc)
        return None
    if not isinstance(data, dict):
        return None
    try:
        return Checkpoint.from_dict(data)
    except (KeyError, TypeError, ValueError) as exc:
        logger.debug("checkpoint from_dict %s failed (%s)", p, exc)
        return None


def list_checkpoints(*, base: Path | None = None) -> list[Checkpoint]:
    """Return every checkpoint on disk (regardless of completion).
    Useful for ``kryon checkpoint list``."""
    d = base or _default_dir()
    if not d.exists():
        return []
    out: list[Checkpoint] = []
    for p in sorted(d.glob("*.json")):
        cp = load_checkpoint(p.stem, base=d)
        if cp is not None:
            out.append(cp)
    return out


def delete_checkpoint(engagement_id: str, *, base: Path | None = None) -> bool:
    """Remove a checkpoint after a successful completion. Returns True
    if a file was deleted."""
    p = checkpoint_path(engagement_id, base=base)
    if not p.exists():
        return False
    try:
        p.unlink()
        return True
    except OSError as exc:
        logger.warning("checkpoint delete %s failed: %s", p, exc)
        return False


def build_checkpoint(
    *,
    engagement_id: str,
    target: str,
    scope: str,
    families: list[str],
    plan_phases: list[Any],
    findings: list[Any],
    new_findings: list[Any],
    goal: Any | None = None,
    verdict_info: dict[str, Any] | None = None,
) -> Checkpoint:
    """Coerce loose orchestrator state into a Checkpoint. Accepts:

    - ``plan_phases``: list of PlanPhase OR dicts with ``to_dict``.
    - ``findings`` / ``new_findings``: list of Finding dataclasses OR
      plain dicts.
    - ``goal``: EngagementGoal-like with ``kind`` / ``raw`` / ``params``.
    """
    phases: list[CheckpointPhase] = []
    for p in plan_phases:
        if isinstance(p, dict):
            phases.append(
                CheckpointPhase(
                    name=str(p.get("name", "")),
                    status=str(p.get("status", "pending")),
                    agent_key=str(p.get("agent_key", "")),
                    max_turns=int(p.get("max_turns", 0) or 0),
                    depends_on=list(p.get("depends_on", []) or []),
                    goal_kind_hint=p.get("goal_kind_hint"),
                )
            )
            continue
        status_obj = getattr(p, "status", None)
        status_str = str(getattr(status_obj, "value", status_obj or "pending"))
        phases.append(
            CheckpointPhase(
                name=str(getattr(p, "name", "")),
                status=status_str,
                agent_key=str(getattr(p, "agent_key", "")),
                max_turns=int(getattr(p, "max_turns", 0) or 0),
                depends_on=list(getattr(p, "depends_on", []) or []),
                goal_kind_hint=getattr(p, "goal_kind_hint", None),
            )
        )

    def _f_dict(f: Any) -> dict[str, Any]:
        if isinstance(f, dict):
            return dict(f)
        out: dict[str, Any] = {}
        for attr in (
            "cwe",
            "severity",
            "host",
            "rule_id",
            "message",
            "evidence",
            "remediation",
            "severity_rank",
            "confidence",
            "needs_verification",
        ):
            val = getattr(f, attr, None)
            if val is not None:
                out[attr] = val
        return out

    goal_dict: dict[str, Any] | None = None
    if goal is not None:
        kind = getattr(goal, "kind", None)
        kind_value = getattr(kind, "value", kind)
        goal_dict = {
            "kind": str(kind_value) if kind_value is not None else "",
            "raw": str(getattr(goal, "raw", "")),
            "params": dict(getattr(goal, "params", {}) or {}),
        }

    return Checkpoint(
        engagement_id=engagement_id,
        target=target,
        scope=scope,
        families=list(families),
        plan_phases=phases,
        findings=[_f_dict(f) for f in findings],
        new_findings=[_f_dict(f) for f in new_findings],
        goal=goal_dict,
        verdict_info=verdict_info,
        saved_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    )
