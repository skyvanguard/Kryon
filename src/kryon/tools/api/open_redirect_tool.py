"""F103 — agent-facing tool wrapper for Open Redirect detector."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.open_redirect import (
    RedirectAnalysis,
    RedirectFinding,
    RedirectObservation,
    analyze_observations,
)

__all__ = ["validate_open_redirect"]


def _finding_to_dict(f: RedirectFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
        "url": f.url,
        "parameter_name": f.parameter_name,
    }


@function_tool
def validate_open_redirect(observations_json: str) -> str:
    """Analyze probe observations for open-redirect vulnerabilities."""
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
            RedirectObservation(
                url=str(entry.get("url") or ""),
                parameter_name=str(entry.get("parameter_name") or ""),
                probe_value=str(entry.get("probe_value") or ""),
                response_status=int(entry.get("response_status") or 0),
                response_location_header=str(entry.get("response_location_header") or ""),
                response_body_snippet=str(entry.get("response_body_snippet") or ""),
            )
        )
    analysis = analyze_observations(observations)
    by_sev: dict[str, int] = {}
    for f in analysis.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return json.dumps(
        {
            "total_observations": analysis.total_observations,
            "finding_count": len(analysis.findings),
            "by_severity": by_sev,
            "findings": [_finding_to_dict(f) for f in analysis.findings],
        },
        ensure_ascii=False,
    )
