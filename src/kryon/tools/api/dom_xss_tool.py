"""F107 — agent-facing tool wrapper for DOM XSS sink detector."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.dom_xss import (
    DomXssAnalysis,
    DomXssFinding,
    JsSnippet,
    analyze_dom_xss,
)

__all__ = ["validate_dom_xss"]


def _finding_to_dict(f: DomXssFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
        "file_path": f.file_path,
        "line": f.line,
        "snippet": f.snippet,
    }


@function_tool
def validate_dom_xss(snippets_json: str) -> str:
    """Scan JavaScript snippets for DOM XSS source→sink patterns.

    Args:
        snippets_json: JSON array of `{file_path, body, line_offset}` objects.
    """
    try:
        raw = json.loads(snippets_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(raw, list):
        return json.dumps({"error": "snippets_json must be a JSON array"})

    snippets = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        snippets.append(
            JsSnippet(
                file_path=str(entry.get("file_path") or ""),
                body=str(entry.get("body") or ""),
                line_offset=int(entry.get("line_offset") or 0),
            )
        )
    analysis = analyze_dom_xss(snippets)
    by_sev: dict[str, int] = {}
    for f in analysis.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return json.dumps(
        {
            "total_snippets": analysis.total_snippets,
            "finding_count": len(analysis.findings),
            "by_severity": by_sev,
            "findings": [_finding_to_dict(f) for f in analysis.findings],
        },
        ensure_ascii=False,
    )
