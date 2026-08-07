"""F176 — Append-only partial finding persistence.

Findings emitted by the model during ``add_finding`` tool calls used to
live only in ChromaDB + the run's in-memory message history. When the
orchestrator's circuit breaker fired (``3 consecutive unproductive
phases``), the reporting phase often never ran, and any structured
findings the model had produced mid-engagement disappeared from the
on-disk report.

This module gives the agent loop a side-channel: every ``add_finding``
call also appends one line of JSON to
``<dir>/<engagement_id>.jsonl``. If the engagement aborts before the
reporting phase, the operator can recover the partial set with
``read_partial_findings(engagement_id)`` and re-merge into the next
run's seed.

Env:
  - ``KRYON_ENGAGEMENT_ID``         current run id (orchestrator sets this).
                                    Empty → persistence silently disabled
                                    (CLI one-off calls don't pollute disk).
  - ``KRYON_PARTIAL_FINDINGS_DIR``  default ``.kryon/partial_findings/``.
  - ``KRYON_PARTIAL_FINDINGS``      ``false`` disables the gate entirely.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _enabled() -> bool:
    return os.environ.get("KRYON_PARTIAL_FINDINGS", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _engagement_id() -> str:
    return os.environ.get("KRYON_ENGAGEMENT_ID", "").strip()


def partial_findings_dir() -> Path:
    raw = os.environ.get("KRYON_PARTIAL_FINDINGS_DIR", "").strip()
    if raw:
        return Path(raw)
    return Path(".kryon") / "partial_findings"


def _partial_path(engagement_id: str | None = None) -> Path | None:
    eid = (engagement_id or _engagement_id()).strip()
    if not eid:
        return None
    # Sanitize the engagement_id so it's a safe filename component —
    # we control the caller in practice (orchestrator sets it), but
    # defense-in-depth is cheap.
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in eid)
    return partial_findings_dir() / f"{safe}.jsonl"


def append_partial_finding(finding: dict[str, Any]) -> bool:
    """Append one finding to the engagement's partial JSONL file.

    Returns True if the line was written. False (silent) on any of:
      * Persistence disabled by env
      * No engagement id set (one-off call, not orchestrated)
      * Finding not a dict
      * IO error (logged at debug level — partial persistence is
        best-effort by design)
    """
    if not _enabled():
        return False
    if not isinstance(finding, dict):
        return False
    path = _partial_path()
    if path is None:
        return False

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(finding, ensure_ascii=False, sort_keys=True))
            fh.write("\n")
        return True
    except OSError as exc:
        logger.debug("partial finding append failed: %s", exc)
        return False


def read_partial_findings(engagement_id: str) -> list[dict[str, Any]]:
    """Read all partial findings for ``engagement_id``. Returns an empty
    list if the file doesn't exist or no lines parse.
    """
    path = _partial_path(engagement_id)
    if path is None or not path.exists():
        return []

    findings: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(doc, dict):
                findings.append(doc)
    except OSError as exc:
        logger.debug("partial finding read failed: %s", exc)
    return findings


def clear_partial_findings(engagement_id: str) -> bool:
    """Delete the partial findings file for ``engagement_id`` after the
    operator has merged it into a final report. Returns True if the
    file existed and was removed.
    """
    path = _partial_path(engagement_id)
    if path is None or not path.exists():
        return False
    try:
        path.unlink()
        return True
    except OSError as exc:
        logger.debug("partial finding clear failed: %s", exc)
        return False
