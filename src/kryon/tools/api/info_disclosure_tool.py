"""F101 — agent-facing tool wrapper for Information Disclosure scanner."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.info_disclosure import (
    DisclosureAnalysis,
    DisclosureFinding,
    DisclosureProbe,
    analyze_probes,
    default_probe_paths,
)

__all__ = ["validate_info_disclosure", "list_disclosure_probe_paths"]


def _finding_to_dict(f: DisclosureFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
        "path": f.path,
    }


@function_tool
def list_disclosure_probe_paths() -> str:
    """Return the canonical list of paths the F101 scanner expects
    the operator to probe."""
    return json.dumps({"paths": default_probe_paths()})


@function_tool
def validate_info_disclosure(probes_json: str) -> str:
    """Analyze a list of HTTP probe results for information disclosure.

    Args:
        probes_json: JSON array of `{path, http_status,
            body_fingerprint, content_length}` objects. Operator
            generates this from probing each path in
            `list_disclosure_probe_paths()`.

    Returns:
        JSON summary with findings sorted by severity.
    """
    try:
        probes_raw = json.loads(probes_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(probes_raw, list):
        return json.dumps({"error": "probes_json must be a JSON array"})

    probes = []
    for entry in probes_raw:
        if not isinstance(entry, dict):
            continue
        probes.append(
            DisclosureProbe(
                path=str(entry.get("path") or ""),
                http_status=int(entry.get("http_status") or 0),
                body_fingerprint=str(entry.get("body_fingerprint") or ""),
                content_length=int(entry.get("content_length") or 0),
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
