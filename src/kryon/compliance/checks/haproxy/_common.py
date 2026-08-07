"""Shared helpers for HAProxy checks.

Reads the effective config tree (/etc/haproxy/haproxy.cfg plus any conf.d
fragments) over SSH. Comment lines (`#...`) are inert and stripped before
matching so a commented-out directive never scores.
"""

from __future__ import annotations

from kryon.compliance.checks.windows._common import make_error, make_result  # noqa: F401 — re-export

HAPROXY_CFG = "cat /etc/haproxy/haproxy.cfg /etc/haproxy/conf.d/*.cfg 2>/dev/null"


def uncommented(cfg: str) -> str:
    """Config text with comment-only lines removed."""
    return "\n".join(ln for ln in cfg.splitlines() if not ln.lstrip().startswith("#"))
