"""F87.6 — agent-facing tool wrapper for the CORS detector."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.cors_detector import (
    CORSAnalysis,
    CORSFinding,
    CORSResponse,
    analyze_cors_response,
)

__all__ = ["validate_cors"]


def _finding_to_dict(f: CORSFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
    }


def _analysis_to_dict(a: CORSAnalysis) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for f in a.findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "allow_origin": a.allow_origin,
        "allow_credentials": a.allow_credentials,
        "allow_methods": list(a.allow_methods),
        "allow_headers": list(a.allow_headers),
        "max_age_seconds": a.max_age_seconds,
        "finding_count": len(a.findings),
        "by_severity": by_severity,
        "findings": [_finding_to_dict(f) for f in a.findings],
    }


@function_tool
def validate_cors(
    headers_json: str,
    request_origin: str,
    request_path: str = "",
    request_method: str = "GET",
) -> str:
    """Static CORS analysis on captured response headers.

    Args:
        headers_json: JSON object of response headers
            (e.g. {"Access-Control-Allow-Origin": "...", ...}).
        request_origin: the Origin the probe sent (e.g.
            "https://attacker.example"). Used to detect reflection.
        request_path: optional path the probe hit (for report context).
        request_method: HTTP method of the probe (GET/POST/...).

    Returns:
        JSON summary with the parsed CORS headers + findings list.
    """
    try:
        headers = json.loads(headers_json) if headers_json else {}
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid headers JSON: {e}"})
    if not isinstance(headers, dict):
        return json.dumps({"error": "headers must be a JSON object"})

    response = CORSResponse(
        request_origin=request_origin,
        request_path=request_path,
        request_method=request_method,
        headers={str(k): str(v) for k, v in headers.items()},
    )
    analysis = analyze_cors_response(response)
    return json.dumps(_analysis_to_dict(analysis), ensure_ascii=False)
