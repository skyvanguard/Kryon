"""F119 — Append-only JSONL forensic audit log.

The log is the **only** source of truth for "what did the agent do
during this engagement". It is:

  - **append-only**: never reopened with truncation, never seeked.
  - **structured JSONL**: one line per action, parseable line-by-line
    without loading the whole file (matters when an engagement
    produces tens of thousands of tool calls).
  - **pre-redacted**: args and results are passed through
    ``kryon.redaction.pan_redactor.redact_sensitive`` before write, so
    the audit file is safe to share with auditors.
  - **hash-anchored**: each entry stores the SHA-256 of the *original*
    (pre-redaction) args + result, so an auditor can verify the agent
    didn't reframe the call after the fact — given the redacted view
    plus the hash, anomalies are detectable.

Env vars
--------
``KRYON_AUDIT_LOG_PATH``      default ``.kryon/audit/{engagement}.jsonl``
``KRYON_AUDIT_LOG_ENABLED``   default ``true``; set ``false`` to disable
                              writes entirely (tests / CI).

This module never raises on write failure — a forensic log that
crashes the engagement defeats its own purpose. Failures are logged
to stderr via ``logging`` instead.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kryon.redaction.pan_redactor import redact_sensitive

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ActionLogEntry:
    """One row of the audit log. Fields chosen so an auditor can answer:
    when (timestamp), in what phase, with what input (args_hash +
    redacted view), what came back (result_hash + redacted view), how
    long it took (duration_ms), and whether it succeeded (status)."""

    timestamp: str
    engagement_id: str
    phase: str
    tool_name: str
    args_hash: str
    args_redacted: str
    result_hash: str
    result_redacted: str
    duration_ms: int
    status: str
    redaction_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _is_disabled() -> bool:
    return os.environ.get("KRYON_AUDIT_LOG_ENABLED", "true").strip().lower() in {"0", "false", "no", "off"}


def _stringify(value: Any) -> str:
    """Render any args/result blob to text so it can be redacted +
    hashed. JSON-encode dicts/lists; coerce everything else via str()."""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list, tuple)):
        try:
            return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
        except Exception:
            return str(value)
    return str(value) if value is not None else ""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ActionLog:
    """Append-only JSONL writer. One instance per engagement."""

    def __init__(self, path: str | Path, engagement_id: str) -> None:
        self.path = Path(path)
        self.engagement_id = engagement_id

    def append(
        self,
        *,
        tool_name: str,
        args: Any,
        result: Any,
        phase: str,
        duration_ms: int = 0,
        status: str = "ok",
    ) -> ActionLogEntry | None:
        """Persist one action. Returns the entry written, or None if
        logging is disabled / write failed (never raises)."""
        if _is_disabled():
            return None

        args_text = _stringify(args)
        result_text = _stringify(result)

        # Hash the ORIGINAL (pre-redaction) text. The redacted view is
        # what humans read; the hash is what makes the audit verifiable.
        args_hash = _sha256(args_text)
        result_hash = _sha256(result_text)

        args_red = redact_sensitive(args_text)
        result_red = redact_sensitive(result_text)
        redaction_count = args_red.total() + result_red.total()

        entry = ActionLogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            engagement_id=self.engagement_id,
            phase=phase,
            tool_name=tool_name,
            args_hash=args_hash,
            args_redacted=args_red.text,
            result_hash=result_hash,
            result_redacted=result_red.text,
            duration_ms=int(duration_ms),
            status=status,
            redaction_count=redaction_count,
        )

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.warning("audit log write failed: %s", exc)
            return None

        return entry


def default_log_path(engagement_id: str) -> Path:
    """Resolve the per-engagement audit log path. Honours
    ``KRYON_AUDIT_LOG_PATH`` (env var); falls back to
    ``.kryon/audit/{engagement_id}.jsonl`` under the current working
    directory."""
    root = os.environ.get("KRYON_AUDIT_LOG_PATH", "").strip()
    if root:
        return Path(root) / f"{engagement_id}.jsonl"
    return Path(".kryon") / "audit" / f"{engagement_id}.jsonl"
