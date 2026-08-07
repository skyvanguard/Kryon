"""Shared helpers for nginx checks.

`nginx -T` dumps the full *effective* configuration (all included files,
parsed) — the authoritative source for what nginx actually runs, so we never
guess at which file a directive lives in.
"""

from __future__ import annotations

from kryon.compliance.checks.windows._common import make_error, make_result  # noqa: F401 — re-export

NGINX_DUMP = "nginx -T 2>/dev/null"


def uncommented(dump: str) -> str:
    """Config text with comment-only lines removed (a `#...` line is inert)."""
    return "\n".join(ln for ln in dump.splitlines() if not ln.lstrip().startswith("#"))
