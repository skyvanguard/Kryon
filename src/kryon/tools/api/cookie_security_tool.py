"""F98 — agent-facing tool wrapper for the cookie security auditor."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.cookie_security import (
    CookieAnalysis,
    CookieFinding,
    analyze_cookies,
)

__all__ = ["validate_cookies"]


def _finding_to_dict(f: CookieFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
        "cookie_name": f.cookie_name,
    }


def _analysis_to_dict(a: CookieAnalysis) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for f in a.findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "cookie_count": a.cookie_count,
        # We deliberately do NOT echo cookie VALUES in the wrapper
        # output — those frequently carry tokens / session ids that
        # should not land in agent context / report archives.
        "cookies": [
            {
                "name": c.name,
                "secure": c.secure,
                "http_only": c.http_only,
                "same_site": c.same_site,
                "domain": c.domain,
                "path": c.path,
                "max_age": c.max_age,
                "has_expires": c.expires is not None,
            }
            for c in a.cookies
        ],
        "finding_count": len(a.findings),
        "by_severity": by_severity,
        "findings": [_finding_to_dict(f) for f in a.findings],
    }


@function_tool
def validate_cookies(
    set_cookie_headers_json: str,
    is_https: bool = True,
) -> str:
    """Static analysis of Set-Cookie response headers.

    Args:
        set_cookie_headers_json: JSON array of Set-Cookie header
            values, one per array entry. Example:
            `["sid=abc; HttpOnly; Secure", "csrf=def; SameSite=Strict"]`.
        is_https: True when the response was served over HTTPS.
            COOKIE-001 fires only on HTTPS.

    Returns:
        JSON summary with parsed cookies (NAMES + FLAGS only — values
        deliberately redacted) + findings list.
    """
    try:
        headers = json.loads(set_cookie_headers_json) if set_cookie_headers_json else []
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})

    if not isinstance(headers, list):
        return json.dumps({"error": "set_cookie_headers_json must be a JSON array"})

    headers_str = [str(h) for h in headers]
    analysis = analyze_cookies(headers_str, is_https=is_https)
    return json.dumps(_analysis_to_dict(analysis), ensure_ascii=False)
