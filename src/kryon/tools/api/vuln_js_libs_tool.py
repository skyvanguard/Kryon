"""F102 — agent-facing tool wrapper for Vulnerable JS Library detector."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.vuln_js_libs import (
    JSLibFinding,
    ScriptObservation,
    analyze_scripts,
)

__all__ = ["validate_js_libraries"]


def _finding_to_dict(f: JSLibFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
        "library": f.library,
        "detected_version": f.detected_version,
        "cve": f.cve,
        "script_src": f.script_src,
    }


@function_tool
def validate_js_libraries(observations_json: str) -> str:
    """Analyze a list of `<script src>` observations for known-vulnerable
    JS library versions.

    Args:
        observations_json: JSON array of `{src, body_fingerprint}` objects.

    Returns:
        JSON summary with findings sorted by severity.
    """
    try:
        obs_raw = json.loads(observations_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(obs_raw, list):
        return json.dumps({"error": "observations_json must be a JSON array"})
    observations = []
    for entry in obs_raw:
        if not isinstance(entry, dict):
            continue
        observations.append(
            ScriptObservation(
                src=str(entry.get("src") or ""),
                body_fingerprint=str(entry.get("body_fingerprint") or ""),
            )
        )
    analysis = analyze_scripts(observations)
    by_sev: dict[str, int] = {}
    for f in analysis.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return json.dumps(
        {
            "total_scripts": analysis.total_scripts,
            "finding_count": len(analysis.findings),
            "by_severity": by_sev,
            "findings": [_finding_to_dict(f) for f in analysis.findings],
        },
        ensure_ascii=False,
    )
