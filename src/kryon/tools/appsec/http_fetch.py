"""HTTP Fetch tool — native Python requests (curl-equivalent with cleaner UA).

Complements the shell/curl path used by most web-pentest skills. A
separate fetch tool is useful when:

- The target WAF fingerprints curl's User-Agent and blocks it.
- You need to follow/manage cookies across multiple requests within
  a single LLM turn (session keep-alive).
- You need a browser-like Accept / Accept-Language / Accept-Encoding
  header set without typing the whole curl invocation.

Exposes ``http_fetch`` as a ``@function_tool`` so the LLM can reach
for it alongside ``shell``/``curl`` based on the target's behaviour.
"""

from __future__ import annotations

import json as _json
from typing import Any

from kryon.sdk.agents import function_tool

try:
    import requests  # type: ignore
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False


_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

_DEFAULT_HEADERS = {
    "User-Agent": _DEFAULT_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.5",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}


@function_tool
def http_fetch(
    url: str,
    method: str = "GET",
    headers_json: str = "",
    body: str = "",
    cookies_json: str = "",
    follow_redirects: bool = True,
    timeout_s: int = 20,
    max_body: int = 8192,
) -> str:
    """Send an HTTP request from Python (native UA, not curl).

    Args:
        url: Target URL (http/https, any method).
        method: HTTP verb (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD).
        headers_json: Optional JSON object of extra headers.
            Example: '{"Authorization": "Bearer abc", "X-Test": "1"}'.
            Default browser-like headers are applied first, then merged
            with this map so the caller can override any header.
        body: Request body for POST/PUT/PATCH. Pass a JSON string for
            content-type application/json or form data otherwise.
        cookies_json: Optional JSON object of cookies.
        follow_redirects: True (default) follows 3xx; False returns the
            first response.
        timeout_s: Per-request timeout; default 20 s.
        max_body: Truncate returned body to this many bytes (default
            8 KB) to keep the tool response LLM-friendly.

    Returns:
        A formatted multi-line string with status, final URL, headers,
        cookies, and the first ``max_body`` bytes of the response body.
        On any transport error returns an ``error`` line + diagnostic.
    """
    if not _REQUESTS_OK:
        return (
            "error: requests library not installed. "
            "Install with: pip install requests"
        )

    try:
        extra_headers: dict[str, str] = {}
        if headers_json:
            parsed = _json.loads(headers_json)
            if isinstance(parsed, dict):
                extra_headers = {str(k): str(v) for k, v in parsed.items()}
        merged_headers = {**_DEFAULT_HEADERS, **extra_headers}

        cookies: dict[str, str] = {}
        if cookies_json:
            parsed = _json.loads(cookies_json)
            if isinstance(parsed, dict):
                cookies = {str(k): str(v) for k, v in parsed.items()}

        method_u = method.upper()
        kwargs: dict[str, Any] = {
            "headers": merged_headers,
            "cookies": cookies,
            "timeout": max(2, timeout_s),
            "allow_redirects": bool(follow_redirects),
            "verify": True,
        }

        # Prefer JSON body when caller passes a parseable object.
        if body and method_u in ("POST", "PUT", "PATCH"):
            stripped = body.strip()
            if stripped.startswith(("{", "[")):
                try:
                    kwargs["json"] = _json.loads(stripped)
                except _json.JSONDecodeError:
                    kwargs["data"] = body
            else:
                kwargs["data"] = body

        resp = requests.request(method_u, url, **kwargs)

    except requests.exceptions.Timeout:
        return f"error: timeout after {timeout_s}s on {method.upper()} {url}"
    except requests.exceptions.ConnectionError as exc:
        return f"error: connection failed: {exc}"[:512]
    except Exception as exc:  # noqa: BLE001
        return f"error: {type(exc).__name__}: {exc}"[:512]

    # Build a concise, LLM-friendly summary.
    lines = [
        f"status: {resp.status_code} {resp.reason}",
        f"final_url: {resp.url}",
        f"redirects: {len(resp.history)}",
    ]

    # Prefer structured headers the LLM actually uses.
    interesting = (
        "content-type", "set-cookie", "location", "server",
        "x-frame-options", "content-security-policy",
        "x-powered-by", "www-authenticate", "access-control-allow-origin",
    )
    hdr_out = []
    for k, v in resp.headers.items():
        if k.lower() in interesting:
            hdr_out.append(f"  {k}: {v}")
    if hdr_out:
        lines.append("headers:")
        lines.extend(hdr_out)

    if resp.cookies:
        lines.append("cookies:")
        for c in resp.cookies:
            lines.append(f"  {c.name}={c.value}")

    try:
        body_text = resp.text
    except Exception:  # noqa: BLE001
        body_text = "<non-text body>"
    truncated = len(body_text) > max_body
    lines.append(f"body ({len(body_text)} bytes{', truncated' if truncated else ''}):")
    lines.append(body_text[:max_body])
    return "\n".join(lines)


__all__ = ["http_fetch"]
