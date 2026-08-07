"""Shared helpers for Cisco IOS / IOS-XE checks.

Audited via `show running-config` over SSH (requires privileged EXEC). We
validate the output actually looks like an IOS config before judging it, so
pointing the framework at a non-Cisco host yields ERROR, never a bogus PASS.
"""

from __future__ import annotations

from kryon.compliance.checks.windows._common import make_error, make_result  # noqa: F401 — re-export

SHOW_RUN = "show running-config"


def looks_like_ios(cfg: str) -> bool:
    """A real IOS running-config uses `!` delimiters and common stanzas."""
    return "!" in cfg and any(k in cfg for k in ("line ", "interface ", "version ", "hostname "))
