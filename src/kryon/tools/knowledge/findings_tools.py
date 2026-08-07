"""Agent-facing tools for the findings pattern library (F64).

These three tools let the LLM feed findings into the pattern library
after an engagement and pull similar prior findings when planning a
new engagement. The retrieval step is the XBOW-style n-days-as-
patterns lookup: every new target benefits from the N previous
engagements' accumulated knowledge.

Tools:

- record_engagement_findings(findings_json, engagement_id, host, tech)
    Persist N findings to the library. Idempotent by content hash —
    safe to call multiple times for the same engagement.

- query_similar_findings(cwe_id, url_pattern, tech, k)
    Retrieve top-k similar prior findings. Plannner_web / the LLM
    calls this BEFORE probing a new target to seed the attack plan
    with known-working patterns.

- findings_library_stats()
    Health + content summary for the library.
"""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool


@function_tool(strict_mode=False)
def record_engagement_findings(
    findings_json: str,
    engagement_id: str = "",
    host: str = "",
    tech_fingerprint: str = "",
) -> str:
    """Persist findings from an engagement into the pattern library.

    The library is shared across engagements; tomorrow's target benefits
    from today's probe run. Idempotent: same (cwe, probe, url_shape,
    host) gets the same id, so calling twice is safe.

    Args:
        findings_json: JSON string — either a list of finding dicts or
            a single wrapping object with a "findings" key. Each finding
            must have at minimum: cwe_id, probe_id, url, severity,
            status, title.
        engagement_id: Optional unique id to tag every finding with the
            engagement they came from (for audit trail / per-engagement
            purge).
        host: Target host. If omitted, inferred from each finding's URL.
        tech_fingerprint: Optional tech stack tag (e.g. "django,postgres,
            nginx") so future probes against similar-tech targets get
            exact matches.

    Returns:
        JSON string with: {"stored": N, "ids": [...],
                           "library_total_after": N}.
    """
    try:
        from kryon.learning.findings_library import add_findings_batch, count_findings
    except ImportError as e:
        return json.dumps({"error": f"findings library unavailable: {e}"})

    try:
        parsed = json.loads(findings_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid findings_json: {e}"})

    if isinstance(parsed, dict):
        findings = parsed.get("findings") or []
    elif isinstance(parsed, list):
        findings = parsed
    else:
        return json.dumps({"error": "findings_json must be a list or {findings: [...]}"})

    if not findings:
        return json.dumps({"stored": 0, "ids": [], "library_total_after": count_findings()})

    # Enrich each finding with engagement metadata
    enriched: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        record = dict(f)
        if engagement_id:
            record.setdefault("engagement_id", engagement_id)
        if host:
            record.setdefault("host", host)
        if tech_fingerprint:
            record.setdefault("tech_fingerprint", tech_fingerprint)
        enriched.append(record)

    try:
        ids = add_findings_batch(enriched)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": f"add_findings_batch failed: {e}"})

    return json.dumps(
        {
            "stored": len(ids),
            "ids": ids,
            "library_total_after": count_findings(),
        }
    )


@function_tool(strict_mode=False)
def findings_library_stats() -> str:
    """Return a compact summary of the findings pattern library.

    Useful for the LLM to report coverage to the user: 'we have 240
    prior findings across 17 engagements, top CWEs are XSS and SQLi'.
    """
    try:
        from kryon.learning.findings_library import stats
    except ImportError as e:
        return json.dumps({"error": str(e)})

    try:
        return json.dumps(stats())
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": str(e)})
