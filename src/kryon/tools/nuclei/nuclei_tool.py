"""F110 — agent-facing tool wrapper for Nuclei."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.nuclei.runner import (
    NucleiFinding,
    NucleiResult,
    NuclieConfig,
    is_nuclei_available,
    run_nuclei,
)

__all__ = ["nuclei_scan", "nuclei_check_available"]


def _finding_to_dict(f: NucleiFinding) -> dict[str, Any]:
    return {
        "template_id": f.template_id,
        "name": f.name,
        "severity": f.severity,
        "nuclei_severity": f.nuclei_severity,
        "matched_at": f.matched_at,
        "target": f.target,
        "description": f.description,
        "reference": list(f.reference),
        "tags": list(f.tags),
        "matcher_name": f.matcher_name,
        "cve_id": f.cve_id,
        "cvss_score": f.cvss_score,
    }


def _result_to_dict(r: NucleiResult) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for f in r.findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "elapsed_seconds": round(r.elapsed_seconds, 3),
        "nuclei_missing": r.nuclei_missing,
        "exit_code": r.exit_code,
        "finding_count": len(r.findings),
        "by_severity": by_severity,
        "findings": [_finding_to_dict(f) for f in r.findings],
        "stderr_excerpt": r.stderr_excerpt,
        "command": r.command,
    }


@function_tool
def nuclei_check_available() -> str:
    """Return whether the `nuclei` binary is installed on PATH."""
    return json.dumps({"available": is_nuclei_available()})


@function_tool
def nuclei_scan(config_json: str) -> str:
    """Run a Nuclei scan with the banca-safe profile.

    Args:
        config_json: JSON object with at minimum `targets: [str]`.
            Optional fields:
              templates_path, tags, severities, rate_limit_per_second,
              bulk_size, concurrency, timeout_seconds,
              overall_timeout_seconds, follow_redirects,
              enable_headless (default false), enable_code_templates
              (default false), auth_header, user_agent.

    Returns:
        JSON summary with finding list sorted by severity.
        `nuclei_missing: true` if binary not on PATH.
    """
    try:
        doc = json.loads(config_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "config_json must be a JSON object"})
    targets = doc.get("targets")
    if not targets or not isinstance(targets, list):
        return json.dumps({"error": "targets: list[str] is required"})

    cfg = NuclieConfig(
        targets=tuple(str(t) for t in targets),
        nuclei_binary=str(doc.get("nuclei_binary") or "nuclei"),
        templates_path=str(doc.get("templates_path") or ""),
        tags=tuple(str(t) for t in (doc.get("tags") or ())) or NuclieConfig(targets=("dummy",)).tags,
        severities=tuple(str(s) for s in (doc.get("severities") or ())) or ("medium", "high", "critical"),
        rate_limit_per_second=int(doc.get("rate_limit_per_second") or 30),
        bulk_size=int(doc.get("bulk_size") or 25),
        concurrency=int(doc.get("concurrency") or 25),
        timeout_seconds=int(doc.get("timeout_seconds") or 5),
        overall_timeout_seconds=int(doc.get("overall_timeout_seconds") or 300),
        no_interactsh=bool(doc.get("no_interactsh", True)),
        enable_code_templates=bool(doc.get("enable_code_templates", False)),
        enable_headless=bool(doc.get("enable_headless", False)),
        silent=bool(doc.get("silent", True)),
        follow_redirects=bool(doc.get("follow_redirects", False)),
        auth_header=str(doc.get("auth_header") or ""),
        user_agent=str(doc.get("user_agent") or "Kryon-Nuclei/1.0 (banca-safe)"),
        extra_args=tuple(str(a) for a in (doc.get("extra_args") or ())),
    )
    result = run_nuclei(cfg)
    return json.dumps(_result_to_dict(result), ensure_ascii=False)
