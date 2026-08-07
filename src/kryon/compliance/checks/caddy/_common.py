"""Shared helpers for Caddy checks.

Reads the Caddyfile over SSH. Caddy is secure-by-default (automatic HTTPS,
TLS 1.2 floor), so the checks look for config that *weakens* those defaults.
Comment lines (`#...`) are stripped before matching.
"""

from __future__ import annotations

from kryon.compliance.checks.windows._common import make_error, make_result  # noqa: F401 — re-export

CADDYFILE = "cat /etc/caddy/Caddyfile 2>/dev/null"


def uncommented(cfg: str) -> str:
    """Caddyfile text with comment-only lines removed."""
    return "\n".join(ln for ln in cfg.splitlines() if not ln.lstrip().startswith("#"))
