"""F92.1 — agent-facing tool wrapper for the Dockerfile auditor."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.container.dockerfile_audit import (
    DockerfileFinding,
    audit_dockerfile,
)

__all__ = ["audit_dockerfile_text"]


def _finding_to_dict(f: DockerfileFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
        "line_number": f.line_number,
    }


@function_tool
def audit_dockerfile_text(dockerfile_text: str) -> str:
    """Static audit a Dockerfile's content against CIS Docker
    Benchmark §4 + banking-pragmatic patterns.

    Args:
        dockerfile_text: the raw Dockerfile content (typically from
            `cat Dockerfile`).

    Returns:
        JSON string with summary + per-rule findings sorted by
        severity (CRITICAL first).
    """
    if not dockerfile_text or not dockerfile_text.strip():
        return json.dumps({"error": "empty Dockerfile"})

    findings = audit_dockerfile(dockerfile_text)
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return json.dumps(
        {
            "finding_count": len(findings),
            "by_severity": by_severity,
            "findings": [_finding_to_dict(f) for f in findings],
        },
        ensure_ascii=False,
    )
