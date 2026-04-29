"""Status line — one-shot summary of agent + system state per turn.

Designed to be called once at the start of each user turn:

    render_status_line(agent, console)
    user_input = prompt(...)

Composable: every optional component (drafts count, ollama health,
last experience) is wrapped in its own try/except. A failing component
is silently omitted; the line never crashes the REPL.

Caches inexpensive checks for ~5 seconds so the line is responsive
without hammering the experience store on every turn.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from kryon.repl.ui.theme import (
    ACCENT_DIM,
    accent,
    dim,
    err,
    ok,
    secondary,
)

logger = logging.getLogger(__name__)


# Truncate skill list to N before the "+M more" overflow marker.
_MAX_VISIBLE_SKILLS = 3

# Cache TTL for non-instant lookups (drafts count, last experience).
# Short enough that newly-created drafts surface almost immediately,
# long enough that we don't hammer disk every turn.
_CACHE_TTL_SEC = 5.0

_cache: dict[str, tuple[float, Any]] = {}


def _cached(key: str, fn):
    """Return cached value for key, refresh if older than _CACHE_TTL_SEC."""
    now = time.time()
    entry = _cache.get(key)
    if entry and (now - entry[0]) < _CACHE_TTL_SEC:
        return entry[1]
    value = fn()
    _cache[key] = (now, value)
    return value


# ---------------------------------------------------------------------------
# Module-level lookups — patched in tests
# ---------------------------------------------------------------------------


def _count_drafts() -> int:
    """Return number of pending drafts in ~/.kryon/drafts/."""
    try:
        from kryon.learning.draft_writer import list_existing_names
        return len(list_existing_names())
    except Exception:  # noqa: BLE001
        return 0


def _ollama_healthy() -> bool:
    """Best-effort Ollama health check. False on any failure."""
    import os

    base = os.environ.get("OLLAMA_HOST") or os.environ.get(
        "KRYON_EMBEDDING_BASE_URL", "http://localhost:11434",
    )
    try:
        import requests
        r = requests.get(f"{base.rstrip('/')}/api/tags", timeout=0.5)
        return r.status_code == 200
    except Exception:  # noqa: BLE001
        return False


def _last_experience_id() -> str | None:
    """Return the id of the most recent experience, or None."""
    try:
        from kryon.learning import list_experiences
        rows = list_experiences(limit=1)
        if rows:
            return rows[0].get("id")
    except Exception:  # noqa: BLE001
        pass
    return None


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def _format_skills(agent: Any) -> str:
    skills = getattr(agent, "_active_skills", None) or []
    if not skills:
        return f"{accent('◆ skills:')} {dim('(none)')}"

    names = [getattr(s, "name", str(s)) for s in skills]
    visible = names[:_MAX_VISIBLE_SKILLS]
    overflow = len(names) - len(visible)
    skill_str = ", ".join(visible)
    if overflow > 0:
        skill_str += f" +{overflow}"

    tools = getattr(agent, "tools", None) or []
    return f"{accent('◆ skills:')} {skill_str} {dim(f'({len(tools)} tools)')}"


def _format_drafts() -> str | None:
    try:
        n = _cached("drafts", _count_drafts)
    except Exception as e:  # noqa: BLE001
        logger.debug("status_line: drafts lookup failed: %s", e)
        return None
    if not n:
        return None
    return f"{secondary(f'📝 {n} drafts')}"


def _format_ollama() -> str | None:
    try:
        healthy = _cached("ollama", _ollama_healthy)
    except Exception as e:  # noqa: BLE001
        logger.debug("status_line: ollama check failed: %s", e)
        return None
    return ok("ollama ✓") if healthy else err("ollama ✗")


def _format_last_exp() -> str | None:
    try:
        eid = _cached("last_exp", _last_experience_id)
    except Exception as e:  # noqa: BLE001
        logger.debug("status_line: last exp lookup failed: %s", e)
        return None
    if not eid:
        return None
    short = eid[:12] if len(eid) > 12 else eid
    return dim(f"last: {short}")


def render_status_line(agent: Any, console: Any) -> None:
    """Print a status header before the user's turn.

    Layout (line 1 always, line 2 only when there's something to say):
        ──────────────────────────  (separator, dim cyan)
        ◆ skills: a, b, c (14 tools)  •  ollama ✓
        📝 3 drafts  •  last: eng_a3f9b2c1d4

    The horizontal rule replaces the visual chunkiness the legacy ASCII
    banner used to provide between turns — without burning 12 lines.

    All optional components degrade silently on error — the REPL
    never crashes from the status line.
    """
    # Visual separator from previous turn's output. Rich.Rule auto-fills
    # the terminal width, no need to compute it ourselves.
    try:
        from rich.rule import Rule
        console.print(Rule(style="dim cyan"))
    except Exception:  # pragma: no cover
        pass

    # Line 1 — skills + ollama
    line1_parts = [_format_skills(agent)]
    olla = _format_ollama()
    if olla:
        line1_parts.append(olla)
    console.print("  •  ".join(line1_parts))

    # Line 2 — drafts + last experience (only when at least one is present)
    line2_parts: list[str] = []
    drafts = _format_drafts()
    if drafts:
        line2_parts.append(drafts)
    last = _format_last_exp()
    if last:
        line2_parts.append(last)
    if line2_parts:
        console.print("  •  ".join(line2_parts))


def clear_cache() -> None:
    """Invalidate cached lookups. Call after operations that change
    state (draft created, experience saved) if the caller wants the
    next status line to reflect the change immediately."""
    _cache.clear()
