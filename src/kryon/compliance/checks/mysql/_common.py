"""Shared helpers for MySQL / MariaDB checks.

Runs the mysql client as the SSH user (local socket / unix_socket auth for
root on Debian/Ubuntu, or ~/.my.cnf) — no credentials embedded. `-N -B`
gives tuples-only, tab-separated batch output.
"""

from __future__ import annotations

from kryon.compliance.checks.windows._common import make_error, make_result  # noqa: F401 — re-export


def mysql_cmd(query: str) -> str:
    """Build a shell command that runs `query` via the local mysql client."""
    return f'mysql -N -B -e "{query}" 2>/dev/null'


def scalar(out: str) -> str:
    """First token of the first non-empty line (COUNT/variable value)."""
    for line in out.splitlines():
        line = line.strip()
        if line:
            # `SHOW VARIABLES LIKE` returns "name\tvalue"; a scalar SELECT returns "value".
            parts = line.split("\t")
            return parts[-1].strip()
    return ""
