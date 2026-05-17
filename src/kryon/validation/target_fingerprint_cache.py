"""F192 — Persisted target fingerprint cache.

F180.B's ``_KNOWN_TARGET_TECH`` map only covers the lab targets we
control end-to-end (juice_shop, dvwa, webgoat, bwapp, mutillidae).
For any other target — a real banking webapp, a custom SaaS, a
random VPS — the map misses, the host hint is empty, and the
applicability gate falls back to narration extraction.

F192 closes that gap by persisting WhatWeb-derived tech_stack to a
``<host>.json`` file in the fingerprint cache dir. Once
``extract_target_tech_stack`` produces a non-empty stack for a host,
we save it. Future engagements against the same host read the saved
fingerprint immediately — even on the very first phase of the new
run, before any tool output has accumulated.

The cache is pure stdlib (json + pathlib) and best-effort: any IO or
JSON error returns an empty result rather than blowing up. Operator
controls the location with ``KRYON_FINGERPRINT_DIR`` (default
``.kryon/target_fingerprints/``).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def _cache_dir() -> Path:
    raw = os.environ.get("KRYON_FINGERPRINT_DIR", "").strip()
    if raw:
        return Path(raw)
    return Path(".kryon") / "target_fingerprints"


def _safe_key(host: str) -> str:
    """Sanitize ``host`` (URL, hostname, host:port) for use as a
    filesystem name. Replaces any non-alphanumeric character (except
    ``-_``.``) with ``_``."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in host)


def fingerprint_path(host: str) -> Path:
    """Resolve the cache file path for ``host``. Exposed for tests."""
    return _cache_dir() / f"{_safe_key(host)}.json"


def save_target_fingerprint(host: str | None, tech_stack: set[str]) -> bool:
    """Persist ``tech_stack`` for ``host``. Returns True on success.

    No-ops (returns False) when host is empty or tech_stack is empty —
    we don't want to overwrite a good cached fingerprint with nothing
    just because the current phase's narration was thin.
    """
    if not host or not isinstance(host, str):
        return False
    if not tech_stack:
        return False

    path = fingerprint_path(host)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "host": host,
            "tech_stack": sorted(tech_stack),
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        path.write_text(
            json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return True
    except OSError as exc:
        logger.debug("F192 save failed for %s: %s", host, exc)
        return False


def load_target_fingerprint(host: str | None) -> set[str]:
    """Read the cached tech_stack for ``host``. Empty set on miss,
    malformed JSON, or IO error."""
    if not host or not isinstance(host, str):
        return set()

    path = fingerprint_path(host)
    if not path.exists():
        return set()

    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("F192 load failed for %s: %s", host, exc)
        return set()

    raw = doc.get("tech_stack") if isinstance(doc, dict) else None
    if not isinstance(raw, list):
        return set()
    return {str(t) for t in raw if isinstance(t, str)}
