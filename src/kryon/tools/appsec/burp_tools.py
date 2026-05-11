"""Burp Suite integration — REST API for Pro edition + mitmproxy fallback.

Burp Suite Professional exposes a REST API on ``http://localhost:1337``
(default) when the user enables ``Settings → Suite → REST API → Enable``
and sets an API key. This module wraps that API with three
``@function_tool``s:

  * ``burp_send_to_repeater`` — replay a captured request with
    modifications (equivalent to right-click → Send to Repeater → modify).
  * ``burp_active_scan`` — trigger an active scan on a URL.
  * ``burp_proxy_history`` — dump recent proxy-intercepted requests.

When Burp is **not** reachable (no Pro license, API disabled), the tools
fall back to the embedded ``HttpSession`` from F50 which provides
mitmproxy-style interception. The fallback is clearly marked in the
return value so the LLM knows which engine handled the request.

Environment variables:
  BURP_API_URL       default: http://localhost:1337
  BURP_API_KEY       required for Pro (unset → fallback to mitmproxy)
  BURP_API_TIMEOUT   seconds; default 15
"""

from __future__ import annotations

import json as _json
import os
from typing import Any

from kryon.sdk.agents import function_tool

try:
    import requests  # type: ignore

    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False


_BURP_URL = os.environ.get("BURP_API_URL", "http://localhost:1337").rstrip("/")
_BURP_KEY = os.environ.get("BURP_API_KEY", "").strip()
_BURP_TIMEOUT = int(os.environ.get("BURP_API_TIMEOUT", "15"))


def _burp_available() -> bool:
    """Probe the Burp REST API once per call (cheap; LLM invocation is rare)."""
    if not (_REQUESTS_OK and _BURP_KEY):
        return False
    try:
        r = requests.get(
            f"{_BURP_URL}/{_BURP_KEY}/v0.1/",
            timeout=3,
        )
        return r.status_code < 500
    except Exception:
        return False


def _fallback_session():
    """Lazy import the F50 HttpSession to avoid a hard dep at module load."""
    try:
        from kryon.webexploit.proxy import HttpSession  # type: ignore

        return HttpSession()
    except Exception:
        return None


@function_tool
def burp_send_to_repeater(
    url: str,
    method: str = "GET",
    headers_json: str = "",
    body: str = "",
    modifications_note: str = "",
    timeout_s: int = 15,
) -> str:
    """Send a request through Burp's Repeater (or mitmproxy fallback).

    Args:
        url: Target URL.
        method: HTTP verb (GET/POST/etc).
        headers_json: Optional JSON object of custom headers.
        body: Request body (JSON or form-encoded string).
        modifications_note: Free-text note recorded alongside the flow —
            useful when exploring payload variants (e.g. "sqli attempt 3").
        timeout_s: Per-request timeout.

    Returns:
        Status + first 4 KB of response body + engine used (burp or mitm).
    """
    if not _REQUESTS_OK:
        return "error: requests library not installed"

    headers: dict[str, str] = {}
    if headers_json:
        try:
            parsed = _json.loads(headers_json)
            if isinstance(parsed, dict):
                headers = {str(k): str(v) for k, v in parsed.items()}
        except _json.JSONDecodeError as exc:
            return f"error: headers_json not valid JSON: {exc}"

    if _burp_available():
        payload: dict[str, Any] = {
            "url": url,
            "method": method.upper(),
            "headers": headers,
            "body": body,
            "note": modifications_note,
        }
        try:
            r = requests.post(
                f"{_BURP_URL}/{_BURP_KEY}/v0.1/send",
                json=payload,
                timeout=timeout_s,
            )
            body_snippet = r.text[:4096]
            return f"[burp-pro] status={r.status_code} bytes={len(r.text)}\n" + body_snippet
        except Exception as exc:  # noqa: BLE001
            # Fall through to mitm fallback rather than returning hard error.
            fallback_reason = f"burp api error: {exc}"
    else:
        fallback_reason = "burp not available (set BURP_API_KEY and enable Suite REST API)"

    # Fallback: use embedded mitmproxy session.
    session = _fallback_session()
    if session is None:
        return f"error: {fallback_reason}; mitmproxy fallback also unavailable"

    try:
        flow = session.send(
            method=method.upper(),
            url=url,
            headers=headers,
            body=body,
            timeout=timeout_s,
        )
        status = getattr(flow.response, "status_code", 0)
        body_bytes = getattr(flow.response, "body", "") or ""
        return (
            f"[mitm-fallback] status={status} bytes={len(body_bytes)}  ({fallback_reason})\n" + str(body_bytes)[:4096]
        )
    except Exception as exc:  # noqa: BLE001
        return f"error: both burp and mitm failed: {exc}"[:512]


@function_tool
def burp_active_scan(
    url: str,
    scan_profile: str = "audit",
    timeout_s: int = 30,
) -> str:
    """Trigger a Burp active scan on the target URL.

    Args:
        url: Target URL (must be in scope).
        scan_profile: Built-in Burp profile name (default ``audit``).
            Common: audit, crawl, crawl-and-audit, passive-only.
        timeout_s: API call timeout (scan itself runs async on server).

    Returns:
        Scan task id + initial progress URL, or a clear error if Burp
        is unavailable. Active scanning in the mitmproxy fallback is NOT
        supported (it's not a scanner), so the fallback returns an
        informational message instead of scanning.
    """
    if not _REQUESTS_OK:
        return "error: requests library not installed"

    if _burp_available():
        try:
            r = requests.post(
                f"{_BURP_URL}/{_BURP_KEY}/v0.1/scan",
                json={"url": url, "profile": scan_profile},
                timeout=timeout_s,
            )
            if r.status_code == 201:
                task_id = r.headers.get("Location", "").rsplit("/", 1)[-1]
                return (
                    f"[burp-pro] scan queued: task_id={task_id} "
                    f"profile={scan_profile}\n"
                    f"poll: GET {_BURP_URL}/{_BURP_KEY}/v0.1/scan/{task_id}"
                )
            return f"[burp-pro] scan failed: {r.status_code} {r.text[:400]}"
        except Exception as exc:  # noqa: BLE001
            return f"error: burp api failed: {exc}"[:512]

    return (
        "[skip] active scanning requires Burp Professional REST API.\n"
        "Set BURP_API_KEY and enable Suite → REST API in Burp settings.\n"
        "No mitmproxy fallback — active scan is scanner-specific."
    )


@function_tool
def burp_proxy_history(
    filter_contains: str = "",
    limit: int = 20,
    timeout_s: int = 15,
) -> str:
    """List recent requests intercepted by Burp Proxy (or mitmproxy fallback).

    Args:
        filter_contains: Only return flows whose URL contains this substring.
        limit: Cap entries returned; default 20.
        timeout_s: API timeout.

    Returns:
        One line per flow: ``METHOD URL -> status  bytes``. When Burp is
        unavailable, uses the in-memory mitmproxy HttpSession for
        recorded flows.
    """
    if not _REQUESTS_OK:
        return "error: requests library not installed"

    if _burp_available():
        try:
            r = requests.get(
                f"{_BURP_URL}/{_BURP_KEY}/v0.1/proxy/history",
                params={"limit": limit},
                timeout=timeout_s,
            )
            if r.status_code != 200:
                return f"[burp-pro] proxy history failed: {r.status_code}"
            data = r.json()
        except Exception as exc:  # noqa: BLE001
            return f"error: burp api failed: {exc}"[:512]

        lines = ["[burp-pro] proxy history:"]
        for entry in data:
            url = entry.get("url", "")
            if filter_contains and filter_contains not in url:
                continue
            lines.append(
                f"  {entry.get('method', ''):6s} {url} -> {entry.get('status', 0)}  {entry.get('response_size', 0)}B"
            )
        return "\n".join(lines)

    # mitmproxy fallback.
    session = _fallback_session()
    if session is None:
        return "error: burp unavailable and mitmproxy fallback not loaded"
    try:
        flows = getattr(session, "history", [])
        lines = [f"[mitm-fallback] history ({len(flows)} flows, filter={filter_contains!r}):"]
        kept = 0
        for f in flows[-limit * 3 :]:  # scan a window, keep <= limit matches
            req_url = getattr(f.request, "url", "")
            if filter_contains and filter_contains not in req_url:
                continue
            status = getattr(f.response, "status_code", 0)
            size = len(getattr(f.response, "body", "") or "")
            lines.append(f"  {getattr(f.request, 'method', ''):6s} {req_url} -> {status}  {size}B")
            kept += 1
            if kept >= limit:
                break
        return "\n".join(lines)
    except Exception as exc:  # noqa: BLE001
        return f"error: mitm history read failed: {exc}"[:512]


__all__ = [
    "burp_send_to_repeater",
    "burp_active_scan",
    "burp_proxy_history",
]
