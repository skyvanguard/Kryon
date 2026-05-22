"""F203.U — IDOR (CWE-639) sequential probe pre_hook.

Banca-safe: GET-only, rate-limited (0.2s between requests), no
modification of foreign resources. Probes a curated list of paths +
sequential / sentinel IDs to flag endpoints that return 200 (vs the
expected 401/403/404) without ownership checks.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from typing import Any

# Curated mix: sequential 1-5 catch trivial enumeration; 100/999 catch
# off-by-N misconfigs; "admin" catches keyword-based bypasses.
_PROBE_IDS: tuple[str, ...] = ("1", "2", "3", "4", "5", "100", "999", "admin")

# Common paths where IDOR shows up. Each base is probed with each ID.
_PROBE_PATHS: tuple[str, ...] = (
    "users",
    "user",
    "api/users",
    "api/v1/users",
    "api/v2/users",
    "orders",
    "api/orders",
    "accounts",
    "api/accounts",
    "transactions",
    "profile",
    "api/profile",
)

_TIMEOUT_S = 5.0
_INTER_REQUEST_S = 0.2


def run(ctx: dict[str, Any]) -> str:
    target = (ctx.get("target") or "").rstrip("/")
    if not target:
        return "IDOR probe skipped: ctx.target empty"

    lines: list[str] = [
        "## IDOR sequential probe (F203.U) — banca-safe GET-only",
        "",
        f"Target: {target}",
        "Probing standard ID-based paths with [1,2,3,4,5,100,999,admin] sentinels.",
        "Look for status=200 on /users/$id (vs expected 401/403/404 → IDOR/CWE-639 candidate).",
        "",
        "| Path | Status | Size | Note |",
        "|------|--------|------|------|",
    ]

    interesting: list[str] = []
    for path in _PROBE_PATHS:
        for pid in _PROBE_IDS:
            url = f"{target}/{path}/{pid}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Kryon-IDOR-Probe/1.0"},
                )
                with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
                    status = resp.status
                    body = resp.read(2048)
                    size = len(body)
                    note = ""
                    if status == 200 and size > 50:
                        note = "**CWE-639 candidate (200 OK on foreign ID)**"
                        interesting.append(f"{url} -> 200 ({size}B)")
                    lines.append(f"| {url} | {status} | {size} | {note} |")
            except urllib.error.HTTPError as e:
                # 4xx is the "correct" response (auth/forbidden/not found)
                if e.code in (200, 301, 302):  # unlikely but defensive
                    note = "** redirected/200, inspect**"
                else:
                    note = ""
                lines.append(f"| {url} | {e.code} | - | {note} |")
            except Exception as e:  # noqa: BLE001 — defensive
                lines.append(f"| {url} | ERROR | - | {type(e).__name__} |")
            time.sleep(_INTER_REQUEST_S)

    lines.append("")
    if interesting:
        lines.append(f"### Interesting (potential CWE-639): {len(interesting)}")
        for it in interesting[:10]:
            lines.append(f"- {it}")
    else:
        lines.append(
            "### No 200-OK responses on standard ID paths — IDOR less likely via "
            "this naive enumeration. Operator should still test with authenticated "
            "session cookies + foreign IDs from a different user."
        )

    return "\n".join(lines)
