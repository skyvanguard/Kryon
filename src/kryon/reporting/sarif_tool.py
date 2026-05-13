"""F89.1 — agent-facing tool wrapper for the SARIF reporter.

Two operation shapes:
  - inline: agent passes findings as JSON; gets SARIF JSON back.
  - to-file: agent passes findings + output path; SARIF written to
    disk, the wrapper returns the path + summary stats.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.reporting.sarif import findings_to_sarif, write_sarif

__all__ = ["emit_sarif"]


@function_tool
def emit_sarif(
    findings_json: str,
    output_path: str = "",
    include_evidence: bool = False,
    tool_version: str = "2.1.0",
) -> str:
    """Convert Kryon findings to SARIF 2.1.0.

    Args:
        findings_json: JSON array of finding dicts. Each dict needs
            at minimum cwe_id + severity; url + host + title strongly
            recommended for inline annotations on the CI side.
        output_path: optional filesystem path. When set, SARIF is
            written there and the tool returns a small summary dict.
            When empty, the full SARIF JSON is returned inline.
        include_evidence: when True, the evidence field is included
            in the SARIF result.message.markdown. DEFAULT FALSE —
            engagement evidence may carry PAN/token fragments.
        tool_version: version string surfaced in the SARIF tool block.

    Returns:
        Inline mode: the full SARIF JSON as a string.
        File mode: JSON summary {output_path, run_count, result_count,
        rule_count}.
    """
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid findings JSON: {e}"})

    if not isinstance(findings, list):
        return json.dumps({"error": "findings_json must be a JSON array"})

    payload = findings_to_sarif(
        findings,
        tool_version=tool_version,
        include_evidence=include_evidence,
    )

    if output_path.strip():
        path = Path(output_path)
        try:
            write_sarif(
                findings,
                path,
                tool_version=tool_version,
                include_evidence=include_evidence,
            )
        except OSError as e:
            return json.dumps({"error": f"write failed: {e}"})
        run = payload["runs"][0]
        return json.dumps(
            {
                "output_path": str(path),
                "run_count": len(payload["runs"]),
                "result_count": len(run["results"]),
                "rule_count": len(run["tool"]["driver"]["rules"]),
            }
        )

    return json.dumps(payload, ensure_ascii=False)
