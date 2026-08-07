"""F132 — Per-target engagement state.

Persisted under ``.kryon/state/<target_slug>.json``. Lets the
orchestrator answer "did I scan this target recently?" without
re-reading every audit JSONL. Used by:

  - F132 deduplication: ``--no-recent N`` reuses the previous
    findings if the last run was less than N minutes ago.
  - F133 baseline diffing: compares this run's findings against the
    previous state to surface NEW / GONE / CHANGED / STABLE buckets.

The file is small (filename + timestamp + findings path), JSON-only,
never grows unboundedly. Safe to commit `.kryon/state/` to git for
audit trail; the actual findings live in ``reports/`` / audit logs.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EngagementState:
    """Last-known state for a single target."""

    target: str
    last_engagement_id: str
    last_run_ts: str  # ISO-8601 with Z suffix
    findings_path: str  # absolute path to last findings.json
    finding_count: int

    def to_dict(self) -> dict:
        return asdict(self)


_SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]")


def target_slug(target: str) -> str:
    """Normalise a target (URL / IP / host) into a filesystem-safe slug.
    Strips scheme, lowercases, collapses runs of separators.
    ``https://www.example.com:443/x`` → ``www.example.com_443_x``"""
    s = (target or "").strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = _SLUG_RE.sub("_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "target"


def default_state_dir() -> Path:
    """Resolve the state directory. Honours ``KRYON_STATE_PATH`` env
    var; falls back to ``.kryon/state/`` under the current working
    directory (companion to ``.kryon/audit/``)."""
    root = os.environ.get("KRYON_STATE_PATH", "").strip()
    if root:
        return Path(root)
    return Path(".kryon") / "state"


def _state_path(target: str, state_dir: Path | None = None) -> Path:
    return (state_dir or default_state_dir()) / f"{target_slug(target)}.json"


def read_state(target: str, *, state_dir: Path | None = None) -> EngagementState | None:
    """Return the persisted state for ``target`` or ``None`` if no
    prior run is recorded. Malformed files are treated as missing."""
    p = _state_path(target, state_dir)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return EngagementState(
            target=str(data.get("target", target)),
            last_engagement_id=str(data.get("last_engagement_id", "")),
            last_run_ts=str(data.get("last_run_ts", "")),
            findings_path=str(data.get("findings_path", "")),
            finding_count=int(data.get("finding_count", 0)),
        )
    except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError) as exc:
        logger.debug("read_state %s failed (%s) — treating as missing", p, exc)
        return None


def write_state(
    target: str,
    *,
    engagement_id: str,
    findings_path: str | Path,
    finding_count: int,
    state_dir: Path | None = None,
) -> EngagementState | None:
    """Persist the state for ``target``. Never raises — a failing
    state write must not abort the engagement."""
    p = _state_path(target, state_dir)
    state = EngagementState(
        target=target,
        last_engagement_id=engagement_id,
        last_run_ts=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        findings_path=str(findings_path),
        finding_count=int(finding_count),
    )
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(state.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return state
    except OSError as exc:
        logger.warning("write_state %s failed: %s", p, exc)
        return None


def minutes_since(state: EngagementState) -> float | None:
    """Minutes elapsed since the recorded ``last_run_ts``. Returns
    ``None`` when the timestamp can't be parsed."""
    if not state or not state.last_run_ts:
        return None
    try:
        ts = state.last_run_ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    delta = datetime.now(timezone.utc) - dt
    return delta.total_seconds() / 60.0
