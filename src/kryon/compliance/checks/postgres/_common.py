"""Shared helpers for PostgreSQL checks.

Queries run as the `postgres` OS user via local peer authentication, so no
credentials are stored. `psql -tA` returns tuples-only, unaligned (pipe-
separated) output that is trivial to parse.
"""

from __future__ import annotations

from kryon.compliance.checks.windows._common import make_error, make_result  # noqa: F401 — re-export


def psql_cmd(query: str) -> str:
    """Build a shell command that runs `query` as the postgres OS user."""
    return f"su -s /bin/sh -c \"psql -tAc '{query}'\" postgres 2>/dev/null"
