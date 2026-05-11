"""Selection telemetry — JSONL log of skill ranking decisions.

Each turn writes one line capturing:
  * which ranking mode was active (priority / hybrid / score)
  * which skills matched the user message
  * their priority + (when available) their experience-derived score
  * which subset was actually selected (after the budget cap)
  * a hash of the user message (or plaintext, opt-in)

This is the dataset the operator inspects with `/skill scores` and the
training data for any future bandit / RL tuning. Banking compliance:
hashed-by-default, plaintext only when `KRYON_SELECTION_LOG_PLAINTEXT=1`
is explicitly set.

ENV vars:
  KRYON_SELECTION_LOG          override path (default: ~/.kryon/selection_log.jsonl)
  KRYON_SELECTION_LOG_DISABLE  set to "1" to suppress writes entirely
  KRYON_SELECTION_LOG_PLAINTEXT set to "1" to also store the verbatim text

All failures are swallowed — telemetry must never break a turn.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


_LOG_PATH_ENV = "KRYON_SELECTION_LOG"
_DISABLE_ENV = "KRYON_SELECTION_LOG_DISABLE"
_PLAINTEXT_ENV = "KRYON_SELECTION_LOG_PLAINTEXT"


def _log_path() -> Path:
    raw = os.environ.get(_LOG_PATH_ENV)
    if raw:
        return Path(raw)
    return Path.home() / ".kryon" / "selection_log.jsonl"


def _is_disabled() -> bool:
    return os.environ.get(_DISABLE_ENV, "").strip() in ("1", "true", "yes")


def _plaintext_enabled() -> bool:
    return os.environ.get(_PLAINTEXT_ENV, "").strip() in ("1", "true", "yes")


def _kryon_version() -> str:
    """Best-effort version detection. Falls back to 'unknown'."""
    try:
        from importlib.metadata import version as _v

        return _v("kryon")
    except Exception:
        return "unknown"


def _hash_msg(msg: str) -> str:
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()


def log_selection(
    user_msg: str,
    ranking_mode: str,
    candidates: list[dict[str, Any]],
    selected: list[str],
) -> None:
    """Append one record to the selection log. Never raises.

    Args:
        user_msg: the operator's input that triggered this match.
        ranking_mode: "priority" | "hybrid" | "score".
        candidates: list of dicts with at least {name, priority}, optionally
            score (may be None).
        selected: subset of candidate names actually loaded into the
            agent's prompt this turn.
    """
    if _is_disabled():
        return

    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "kryon_version": _kryon_version(),
        "ranking_mode": ranking_mode,
        "candidates": candidates,
        "selected": selected,
        "user_msg_hash": _hash_msg(user_msg or ""),
    }
    if _plaintext_enabled():
        record["user_msg"] = user_msg

    try:
        path = _log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:  # noqa: BLE001
        # Telemetry is best-effort. Never propagate.
        logger.debug("selection_telemetry: write failed: %s", e)


def read_recent(limit: int = 20) -> list[dict[str, Any]]:
    """Return the `limit` most recent records, newest first. Empty on miss."""
    path = _log_path()
    if not path.is_file():
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except Exception as e:  # noqa: BLE001
        logger.debug("selection_telemetry: read failed: %s", e)
        return []

    out: list[dict[str, Any]] = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(out) >= limit:
            break
    return out
