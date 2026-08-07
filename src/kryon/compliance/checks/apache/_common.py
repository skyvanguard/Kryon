"""Shared helpers for Apache HTTPD checks.

Apache has no single effective-config dump, so we grep the config tree
(/etc/apache2 on Debian, /etc/httpd on RHEL). Each command first lists those
directories (a presence probe) so a missing directive on a real Apache host
is distinguishable from "Apache isn't installed here" (ERROR, not a verdict).
"""

from __future__ import annotations

from kryon.compliance.checks.windows._common import make_error, make_result  # noqa: F401 — re-export

_DIRS = "/etc/apache2 /etc/httpd"
_SPLIT = "---KRYON-SPLIT---"


def apache_grep(directive_regex: str) -> str:
    """List the config dirs (presence probe), then grep a directive across them."""
    return (
        f"ls -d {_DIRS} 2>/dev/null; echo '{_SPLIT}'; "
        f"grep -rhiE '{directive_regex}' {_DIRS} 2>/dev/null | grep -vE '^[[:space:]]*#'"
    )


def split_probe(out: str) -> tuple[bool, list[str]]:
    """Split the probe output into (apache_present, matching_config_lines)."""
    parts = out.split(_SPLIT, 1)
    present = bool(parts[0].strip())
    body = parts[1] if len(parts) > 1 else ""
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    return present, lines
