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
def query_similar_findings(
    query: str = "",
    cwe_id: str = "",
    url_pattern: str = "",
    tech_fingerprint: str = "",
    k: int = 5,
) -> str:
    """Retrieve top-k similar findings from the pattern library.

    Call this at the START of a new engagement to enrich the attack
    plan with known-working patterns. Typical use from planner_web:

    1. Crawl gives a URL like /api/account/00012345
    2. Extract url_shape "/api/account/<int>"
    3. query_similar_findings(url_pattern="/api/account/<int>") returns
       every prior finding with that shape — CWE-639 IDORs, CWE-89
       SQLi, etc — so the planner boosts those specific probes.

    Args:
        query: Free-text query; combined with filters. e.g.
            "IDOR on account endpoints" biases retrieval semantically.
        cwe_id: Restrict to one CWE class (e.g. "CWE-89").
        url_pattern: Exact url_shape lookup (e.g. "/api/account/<int>").
            When set, this becomes the primary retrieval key.
        tech_fingerprint: Restrict to findings against similar tech
            stack ("django,postgres").
        k: Max hits to return (default 5).

    Returns:
        JSON string with {"count": N, "findings": [...]} — each finding
        includes: score, cwe_id, probe_id, url_shape, title, evidence,
        compliance_citations, host, severity, status.
    """
    try:
        from kryon.learning.findings_library import recall_by_url_shape, recall_similar
    except ImportError as e:
        return json.dumps({"count": 0, "findings": [], "error": str(e)})

    hits: list[dict[str, Any]] = []

    # Exact url_shape lookup takes precedence when set
    if url_pattern:
        try:
            exact = recall_by_url_shape(url_pattern, k=k)
        except Exception:  # noqa: BLE001
            exact = []
        # Synthesize a score=1.0 for exact shape matches
        for f in exact:
            f["score"] = 1.0
            hits.append(f)

    # Fill remaining slots via semantic query
    if len(hits) < k:
        remaining = k - len(hits)
        query_parts: list[str] = []
        if query:
            query_parts.append(query)
        if cwe_id:
            query_parts.append(f"cwe={cwe_id}")
        if url_pattern:
            query_parts.append(f"url={url_pattern}")
        if tech_fingerprint:
            query_parts.append(f"tech={tech_fingerprint}")
        composite = " | ".join(query_parts) or "web findings"

        try:
            semantic = recall_similar(
                composite,
                k=remaining,
                filter_cwe=cwe_id or None,
                filter_tech=tech_fingerprint or None,
            )
        except Exception:  # noqa: BLE001
            semantic = []

        # De-duplicate by id against exact hits already in `hits`
        existing_ids = {h.get("id") for h in hits}
        for f in semantic:
            if f.get("id") in existing_ids:
                continue
            hits.append(f)

    # Trim output to keep token cost down
    lean: list[dict[str, Any]] = []
    for h in hits[:k]:
        lean.append(
            {
                "score": round(float(h.get("score") or 0.0), 3),
                "cwe_id": h.get("cwe_id"),
                "probe_id": h.get("probe_id"),
                "severity": h.get("severity"),
                "status": h.get("status"),
                "title": h.get("title"),
                "url_shape": h.get("url_shape"),
                "host": h.get("host"),
                "tech_fingerprint": h.get("tech_fingerprint"),
                "compliance_citations": h.get("compliance_citations") or [],
                "evidence": (h.get("evidence") or "")[:256],
                "remediation": (h.get("remediation") or "")[:256],
            }
        )

    return json.dumps({"count": len(lean), "findings": lean})


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
