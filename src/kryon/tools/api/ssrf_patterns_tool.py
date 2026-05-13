"""F106 — agent-facing tool wrapper for SSRF pattern detector."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.ssrf_patterns import (
    SsrfAnalysis,
    SsrfCodeSnippet,
    SsrfFinding,
    SsrfParameter,
    analyze_ssrf,
)

__all__ = ["validate_ssrf_patterns"]


def _finding_to_dict(f: SsrfFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
        "location": f.location,
    }


@function_tool
def validate_ssrf_patterns(input_json: str) -> str:
    """Run SSRF static analysis over discovered parameters + code snippets.

    Args:
        input_json: JSON object with `{parameters: [...], snippets: [...]}`.
            parameters items: `{name, sample_value, location, endpoint}`.
            snippets items: `{language, file_path, body, line_offset}`.

    Returns:
        JSON summary.
    """
    try:
        doc = json.loads(input_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "input_json must be a JSON object"})

    params: list[SsrfParameter] = []
    for entry in doc.get("parameters") or []:
        if not isinstance(entry, dict):
            continue
        params.append(
            SsrfParameter(
                name=str(entry.get("name") or ""),
                sample_value=str(entry.get("sample_value") or ""),
                location=str(entry.get("location") or "query"),
                endpoint=str(entry.get("endpoint") or ""),
            )
        )

    snippets: list[SsrfCodeSnippet] = []
    for entry in doc.get("snippets") or []:
        if not isinstance(entry, dict):
            continue
        snippets.append(
            SsrfCodeSnippet(
                language=str(entry.get("language") or "").lower(),
                file_path=str(entry.get("file_path") or ""),
                body=str(entry.get("body") or ""),
                line_offset=int(entry.get("line_offset") or 0),
            )
        )
    analysis = analyze_ssrf(params, snippets)
    by_sev: dict[str, int] = {}
    for f in analysis.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return json.dumps(
        {
            "total_parameters": analysis.total_parameters,
            "total_snippets": analysis.total_snippets,
            "finding_count": len(analysis.findings),
            "by_severity": by_sev,
            "findings": [_finding_to_dict(f) for f in analysis.findings],
        },
        ensure_ascii=False,
    )
