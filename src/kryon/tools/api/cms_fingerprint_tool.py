"""F104 — agent-facing tool wrapper for CMS/framework fingerprinting."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.cms_fingerprint import (
    FingerprintFinding,
    FingerprintObservation,
    analyze_fingerprint,
)

__all__ = ["validate_cms_fingerprint"]


def _finding_to_dict(f: FingerprintFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
        "detected_tech": f.detected_tech,
        "detected_version": f.detected_version,
    }


@function_tool
def validate_cms_fingerprint(observation_json: str) -> str:
    """Identify the CMS / framework behind a target.

    Args:
        observation_json: JSON object with
            `{url, headers: [[name, value], ...], body_snippet, cookie_names, observed_paths}`.

    Returns:
        JSON summary with findings.
    """
    try:
        doc = json.loads(observation_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "observation_json must be a JSON object"})

    headers_raw = doc.get("headers") or []
    headers: list[tuple[str, str]] = []
    for entry in headers_raw:
        if isinstance(entry, (list, tuple)) and len(entry) == 2:
            headers.append((str(entry[0]), str(entry[1])))

    obs = FingerprintObservation(
        url=str(doc.get("url") or ""),
        headers=tuple(headers),
        body_snippet=str(doc.get("body_snippet") or ""),
        cookie_names=tuple(str(c) for c in (doc.get("cookie_names") or ())),
        observed_paths=tuple(str(p) for p in (doc.get("observed_paths") or ())),
    )
    analysis = analyze_fingerprint(obs)
    by_sev: dict[str, int] = {}
    for f in analysis.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return json.dumps(
        {
            "url": analysis.url,
            "finding_count": len(analysis.findings),
            "by_severity": by_sev,
            "findings": [_finding_to_dict(f) for f in analysis.findings],
        },
        ensure_ascii=False,
    )
