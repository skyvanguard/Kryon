"""F97 — agent-facing tool wrapper for the security headers auditor."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.security_headers import (
    HSHFinding,
    HTTPResponse,
    SecurityHeadersAnalysis,
    analyze_security_headers,
)

__all__ = ["validate_security_headers"]


def _finding_to_dict(f: HSHFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
    }


def _analysis_to_dict(a: SecurityHeadersAnalysis) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for f in a.findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "csp_present": a.csp_present,
        "hsts_present": a.hsts_present,
        "finding_count": len(a.findings),
        "by_severity": by_severity,
        "findings": [_finding_to_dict(f) for f in a.findings],
    }


@function_tool
def validate_security_headers(
    headers_json: str,
    url: str = "",
    method: str = "GET",
    is_https: bool = True,
) -> str:
    """Static analysis of HTTP response security headers.

    Args:
        headers_json: JSON object of response headers (e.g.
            `{"Content-Type": "...", "Server": "nginx/1.18.0", ...}`).
        url: optional URL for the report context.
        method: HTTP method of the probe.
        is_https: True when the probe was over HTTPS. HSTS check fires
            only on HTTPS responses.

    Returns:
        JSON summary with parsed CSP/HSTS presence flags + findings.
    """
    try:
        headers = json.loads(headers_json) if headers_json else {}
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid headers JSON: {e}"})
    if not isinstance(headers, dict):
        return json.dumps({"error": "headers must be a JSON object"})

    response = HTTPResponse(
        url=url,
        method=method,
        is_https=is_https,
        headers={str(k): str(v) for k, v in headers.items()},
    )
    analysis = analyze_security_headers(response)
    return json.dumps(_analysis_to_dict(analysis), ensure_ascii=False)
