"""F89.1 — SARIF 2.1.0 reporter.

Convert Kryon findings into the **Static Analysis Results Interchange
Format** (SARIF 2.1.0) — the OASIS standard format that GitHub Code
Scanning, GitLab Security Dashboard, Azure DevOps, and most modern
security tooling accept as ingestion input. Producing SARIF is the
foundation for F89.2 (GitHub Action) and F89.3 (GitLab CI plugin):
the CI runner executes Kryon, Kryon writes a SARIF file, the CI
platform displays the findings as PR annotations + a security
dashboard widget.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub ingestion contract: https://docs.github.com/en/code-security/
code-scanning/integrating-with-code-scanning/sarif-support-for-
code-scanning

This module is a PURE transform. Inputs are dicts (the Kryon finding
shape used by `findings_library`); output is a dict matching SARIF
2.1.0. No I/O beyond the optional `write_sarif` helper that
serializes the dict to disk.

Mapping (Kryon → SARIF):

  finding.cwe_id            → result.ruleId + rules[i].id
  finding.severity          → result.level (see _severity_to_level)
  finding.title             → result.message.text + rule.shortDescription
  finding.evidence          → result.message.markdown (optional)
  finding.url               → location.physicalLocation.artifactLocation.uri
  finding.host              → location.physicalLocation.uriBaseId
  finding.url_shape         → property bag (kryon/url_shape)
  finding.id                → fingerprints["kryon/finding/v1"]

Banking-safety:
  - The reporter does NOT include `evidence` body content in the
    SARIF message by default. Engagement transcripts often contain
    PAN fragments / token values that should not land in CI logs.
    Operators that explicitly want full evidence pass
    `include_evidence=True`.
  - URL stays in the result (it's a public-ish identifier), but the
    severity-based level keeps the report banca-actionable.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

__all__ = [
    "findings_to_sarif",
    "write_sarif",
    "SARIF_VERSION",
    "SARIF_SCHEMA",
    "DEFAULT_TOOL_VERSION",
]


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DEFAULT_TOOL_VERSION = "2.1.0"

# SARIF level enum (case-sensitive). The spec also defines "none" for
# informational results; we use it for CWE entries that are pure
# disclosure with no remediation pressure.
_SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}


def _severity_to_level(severity: str) -> str:
    """Coerce Kryon severity (free-form, sometimes lower-case) into
    one of the four SARIF levels. Unknown values default to 'warning'
    (the safer choice — better to surface an unclear finding than
    silently classify it as 'none')."""
    return _SEVERITY_TO_LEVEL.get(severity.upper().strip(), "warning")


def _cwe_number(cwe_id: str) -> str | None:
    """Extract the numeric part of a CWE-NNN id. Returns None for
    malformed inputs so the helpUri builder can fall back to a
    generic CWE root link."""
    if not isinstance(cwe_id, str):
        return None
    cleaned = cwe_id.upper().replace("CWE-", "").replace("CWE_", "").strip()
    return cleaned if cleaned.isdigit() else None


def _help_uri_for_cwe(cwe_id: str) -> str:
    """https://cwe.mitre.org/data/definitions/<N>.html — the canonical
    CWE landing page. Falls back to the CWE root when the id is
    malformed."""
    num = _cwe_number(cwe_id)
    if num is None:
        return "https://cwe.mitre.org/"
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def _build_rule(cwe_id: str, title_hint: str = "") -> dict[str, Any]:
    """Build one reporting descriptor (SARIF rule). The same rule
    is referenced by every finding sharing the cwe_id; SARIF
    expects rules deduplicated across the run."""
    return {
        "id": cwe_id,
        "name": cwe_id.replace("-", ""),  # CWE-89 → CWE89
        "shortDescription": {
            "text": title_hint[:120] if title_hint else f"Finding pattern {cwe_id}",
        },
        "helpUri": _help_uri_for_cwe(cwe_id),
        "defaultConfiguration": {"level": "warning"},
    }


def _fingerprint_for_finding(finding: dict[str, Any]) -> str:
    """Stable fingerprint over (cwe, host, url_shape, probe_id). The
    same finding produced twice yields the same fingerprint so
    GitHub's deduplication recognizes it as one alert across runs."""
    payload = "|".join(str(finding.get(k, "") or "") for k in ("cwe_id", "host", "url_shape", "probe_id"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _build_location(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Build one SARIF location. Returns None when the finding has
    no URL — a SARIF result without a location is still valid, the
    consumer just can't render it inline."""
    url = finding.get("url") or ""
    if not url:
        return None
    parsed = urlparse(url)
    # Use the full URL as artifactLocation.uri. GitHub's SARIF
    # ingester accepts absolute URLs; GitLab maps them to "external
    # location" cards.
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": url},
        },
    }
    if parsed.netloc:
        location["physicalLocation"]["artifactLocation"]["uriBaseId"] = parsed.netloc
    return location


def _build_result(
    finding: dict[str, Any],
    *,
    include_evidence: bool,
) -> dict[str, Any]:
    """Build one SARIF result entry."""
    cwe_id = str(finding.get("cwe_id") or "CWE-Unknown")
    severity = str(finding.get("severity") or "MEDIUM")
    title = str(finding.get("title") or f"Finding {cwe_id}")

    message_text = title[:1000]  # SARIF doesn't cap but consumers do
    message: dict[str, Any] = {"text": message_text}

    if include_evidence:
        evidence = finding.get("evidence")
        if evidence:
            # Markdown rendering on GitHub Code Scanning; clipped at
            # 4 KB so a stray base64 dump doesn't make every alert
            # huge.
            message["markdown"] = str(evidence)[:4096]

    result: dict[str, Any] = {
        "ruleId": cwe_id,
        "level": _severity_to_level(severity),
        "message": message,
        "fingerprints": {
            "kryon/finding/v1": _fingerprint_for_finding(finding),
        },
        "properties": {
            "kryon/url_shape": str(finding.get("url_shape") or ""),
            "kryon/tech_fingerprint": str(finding.get("tech_fingerprint") or ""),
            "kryon/severity": severity,
        },
    }
    if fid := finding.get("id"):
        result["properties"]["kryon/finding_id"] = str(fid)

    location = _build_location(finding)
    if location is not None:
        result["locations"] = [location]

    return result


def findings_to_sarif(
    findings: list[dict[str, Any]],
    *,
    tool_version: str = DEFAULT_TOOL_VERSION,
    tool_name: str = "Kryon",
    information_uri: str = "https://github.com/skyvanguard/Kryon",
    include_evidence: bool = False,
    run_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert a list of Kryon findings into a SARIF 2.1.0 log dict.

    Args:
        findings: list of finding dicts (the shape used by
            findings_library — at minimum cwe_id, severity; url, host,
            title strongly recommended).
        tool_version: version string for the SARIF tool block.
        tool_name: human-readable tool name.
        information_uri: URL the SARIF consumer links from the
            tool driver block.
        include_evidence: when True, the evidence field gets surfaced
            into result.message.markdown. DEFAULT FALSE for banking
            engagements — evidence may carry token / PAN fragments.
        run_metadata: optional dict merged into run.properties for
            engagement tracking (engagement_id, client, started_at, …).

    Returns:
        A dict matching SARIF 2.1.0. Pass to `write_sarif` or
        `json.dumps` directly.
    """
    # Build the rules block — one entry per distinct CWE.
    rules_by_id: dict[str, dict[str, Any]] = {}
    for finding in findings:
        cwe_id = str(finding.get("cwe_id") or "CWE-Unknown")
        if cwe_id in rules_by_id:
            continue
        title_hint = str(finding.get("title") or "")
        rules_by_id[cwe_id] = _build_rule(cwe_id, title_hint)

    results = [_build_result(f, include_evidence=include_evidence) for f in findings]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": information_uri,
                "rules": list(rules_by_id.values()),
            },
        },
        "results": results,
    }
    if run_metadata:
        run["properties"] = dict(run_metadata)

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [run],
    }


def write_sarif(
    findings: list[dict[str, Any]],
    out_path: Path,
    **kwargs: Any,
) -> Path:
    """Write `findings` as SARIF JSON to `out_path`. Creates parents
    if missing. kwargs forwarded to `findings_to_sarif`. Returns the
    written path."""
    payload = findings_to_sarif(findings, **kwargs)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path
