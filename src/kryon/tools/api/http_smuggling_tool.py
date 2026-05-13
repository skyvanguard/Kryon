"""F105 — agent-facing tool wrapper for HTTP smuggling analyzer."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.http_smuggling import (
    SmugglingAnalysis,
    SmugglingFinding,
    SmugglingProbe,
    analyze_probes,
)

__all__ = ["validate_http_smuggling"]


def _finding_to_dict(f: SmugglingFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
        "probe_type": f.probe_type,
    }


@function_tool
def validate_http_smuggling(probes_json: str) -> str:
    """Classify operator-captured HTTP smuggling probe outcomes."""
    try:
        raw = json.loads(probes_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(raw, list):
        return json.dumps({"error": "probes_json must be a JSON array"})

    probes = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        probes.append(
            SmugglingProbe(
                probe_type=str(entry.get("probe_type") or ""),
                http_status=int(entry.get("http_status") or 0),
                response_time_seconds=float(entry.get("response_time_seconds") or 0.0),
                body_fingerprint=str(entry.get("body_fingerprint") or ""),
                additional_responses_observed=int(entry.get("additional_responses_observed") or 0),
                notes=str(entry.get("notes") or ""),
            )
        )
    analysis = analyze_probes(probes)
    by_sev: dict[str, int] = {}
    for f in analysis.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return json.dumps(
        {
            "total_probes": analysis.total_probes,
            "finding_count": len(analysis.findings),
            "by_severity": by_sev,
            "findings": [_finding_to_dict(f) for f in analysis.findings],
        },
        ensure_ascii=False,
    )
