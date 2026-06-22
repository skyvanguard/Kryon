"""Atomic, lock-guarded JSON state persistence.

The engagement queue (``.kryon/queue.json``) and the scheduler
(``.kryon/schedule.json``) are read-modify-written by potentially
concurrent ``kryon`` processes (e.g. ``kryon queue process --concurrency
N`` spawning child engagements). The original ``write_text`` /
``read_text`` pair had two problems:

  1. **Torn writes** — a reader could observe a half-written file, or a
     crash mid-write could truncate it.
  2. **Lost updates** — two writers racing read-modify-write would clobber
     each other.

This module fixes both with a cross-platform ``filelock`` (works on
Windows, unlike ``fcntl``) around an atomic ``os.replace`` write. Both
helpers degrade gracefully: a lock timeout logs and proceeds best-effort
rather than losing the operator's data.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout

logger = logging.getLogger(__name__)

# How long to wait for the state lock before proceeding best-effort.
LOCK_TIMEOUT_S = 10


def _lock_for(path: Path) -> FileLock:
    return FileLock(str(path) + ".lock")


def read_json_locked(path: Path, *, default: Any) -> Any:
    """Read JSON from ``path`` under the state lock.

    Returns ``default`` if the file is missing, unreadable, or corrupt.
    """
    if not path.exists():
        return default
    try:
        with _lock_for(path).acquire(timeout=LOCK_TIMEOUT_S):
            return json.loads(path.read_text(encoding="utf-8"))
    except Timeout:
        logger.warning("state lock busy for %s — reading without lock", path)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("state read failed (%s) — using default", exc)
            return default
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("state read failed (%s) — using default", exc)
        return default


def write_json_atomic(path: Path, data: Any) -> None:
    """Atomically write ``data`` as JSON to ``path`` under the state lock.

    Writes to a temp file in the same directory, then ``os.replace`` —
    atomic on POSIX and Windows when source and destination share a
    filesystem. Never raises; failures are logged.
    """
    payload = json.dumps(data, ensure_ascii=False, indent=2)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _lock_for(path).acquire(timeout=LOCK_TIMEOUT_S):
            _atomic_replace(path, payload)
    except Timeout:
        logger.warning("state lock busy for %s — writing best-effort", path)
        try:
            _atomic_replace(path, payload)
        except OSError as exc:
            logger.warning("state write failed: %s", exc)
    except OSError as exc:
        logger.warning("state write failed: %s", exc)


def update_json_locked(path: Path, mutator, *, default: Any) -> Any:
    """Read-modify-write ``path`` under a SINGLE lock acquisition — the only race-free way
    to claim/transition shared state (separate read_json_locked + write_json_atomic calls
    have a TOCTOU window between them). ``mutator(data)`` gets the current JSON (or
    ``default`` if missing/corrupt) and returns ``(new_data | None, result)``: when
    ``new_data`` is not None it is written atomically; ``result`` is returned to the caller.
    On lock timeout it proceeds best-effort (correct for a single writer)."""

    def _do() -> Any:
        try:
            data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else default
        except (json.JSONDecodeError, OSError):
            data = default
        new_data, result = mutator(data)
        if new_data is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_replace(path, json.dumps(new_data, ensure_ascii=False, indent=2))
        return result

    try:
        with _lock_for(path).acquire(timeout=LOCK_TIMEOUT_S):
            return _do()
    except Timeout:
        logger.warning("state lock busy for %s — read-modify-write best-effort", path)
        return _do()


def _atomic_replace(path: Path, payload: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        # Clean up the temp file on any failure so we don't litter .tmp files.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
