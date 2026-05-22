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
import re
import subprocess
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

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
    cmd = [
        "sqlmap",
        "-u",
        url,
        "--batch",
        "--level=2",
        "--risk=2",
        "--threads=5",
        "--timeout=8",
        "--ignore-code=401",
        "--technique=B",
        "--random-agent",
    ]
    if endpoint.get("method") == "POST":
        if "data" in endpoint:
            cmd.extend(["--data", endpoint["data"]])
        if endpoint.get("content_type"):
            cmd.extend(["--headers", f"Content-Type: {endpoint['content_type']}"])
    logger.info("F191 sqlmap on %s", url)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
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
        f"[F191] endpoints probed: {len(results)} | "
        f"VULNERABLE: {len(positive)} | clean: {len(negative)}",
        "",
    ]
    for r in positive:
        lines.append(
            f"**VULNERABLE** {r['method']} {r['endpoint']} (status {r['status']})"
        )
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
        # Strip query string for the responsive probe; sqlmap re-attaches it.
        probe_url = url.split("?", 1)[0]
        status = _probe_responsive(probe_url)
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

    return _summarize_endpoint_results(results)
