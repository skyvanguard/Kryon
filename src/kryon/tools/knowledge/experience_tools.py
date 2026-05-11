"""
KRYON Experience Tools — agent-facing access to the self-improving loop.

These tools let agents query the store of prior engagement experiences
so they can bias their plan toward attack chains that have worked
against similar targets before.
"""

from __future__ import annotations

from typing import Any

from kryon.sdk.agents import function_tool


@function_tool
def recall_similar_experiences(
    host_or_profile: str,
    ports_csv: str | None = None,
    tech_csv: str | None = None,
    k: int = 3,
) -> dict[str, Any]:
    """Recall attack chains from prior engagements against similar targets.

    Use this at the **start** of an engagement, right after you know
    the target's host and (ideally) a few open ports, to get hints
    about which tool sequences have worked before. The result is
    advisory — treat it as prior knowledge, not a script.

    Args:
        host_or_profile: Host/IP/URL or a free-text profile description.
        ports_csv: Optional comma-separated open ports (e.g. "80,443,22").
        tech_csv: Optional comma-separated detected tech (e.g.
            "apache,wordpress,php").
        k: Max number of similar experiences to return (default 3).

    Returns:
        Dict with:
          - count: number of matches
          - experiences: list of hit dicts, each with:
              - score: similarity (higher is better)
              - host, outcome, duration_s, summary
              - chain: list of {tool, args, status}
        On cold start (no prior experiences), returns count=0 and an
        empty list.
    """
    try:
        from kryon.learning import recall_similar
    except Exception as e:
        return {"count": 0, "experiences": [], "error": f"learning module unavailable: {e}"}

    query_parts: list[str] = [f"host={host_or_profile}"]
    if ports_csv:
        query_parts.append(f"ports={ports_csv}")
    if tech_csv:
        query_parts.append(f"tech={tech_csv}")
    query = " | ".join(query_parts)

    try:
        hits = recall_similar(query, k=k)
    except Exception as e:
        return {"count": 0, "experiences": [], "error": str(e)}

    lean_hits = []
    for h in hits:
        chain = h.get("chain") or []
        lean_hits.append(
            {
                "score": round(float(h.get("score") or 0.0), 3),
                "host": (h.get("target_profile") or {}).get("host", ""),
                "outcome": h.get("outcome"),
                "duration_s": h.get("duration_s"),
                "summary": h.get("summary"),
                "chain": [
                    {
                        "tool": step.get("tool"),
                        "args": (step.get("args") or "")[:200],
                        "status": step.get("status"),
                    }
                    for step in chain
                ],
            }
        )
    return {"count": len(lean_hits), "experiences": lean_hits}


@function_tool
def list_recent_experiences(limit: int = 10) -> dict[str, Any]:
    """List the most recent engagement experiences stored in KRYON.

    Useful for self-inspection or when the user asks "what have we done
    before".

    Args:
        limit: Maximum number of experiences to return.

    Returns:
        Dict with count + list of experience summaries.
    """
    try:
        from kryon.learning import list_experiences
    except Exception as e:
        return {"count": 0, "experiences": [], "error": f"learning module unavailable: {e}"}

    try:
        rows = list_experiences(limit=limit)
    except Exception as e:
        return {"count": 0, "experiences": [], "error": str(e)}

    summaries = [
        {
            "id": r.get("id"),
            "created_at": r.get("created_at"),
            "host": (r.get("target_profile") or {}).get("host", ""),
            "outcome": r.get("outcome"),
            "duration_s": r.get("duration_s"),
            "chain_length": len(r.get("chain") or []),
            "summary": r.get("summary"),
        }
        for r in rows
    ]
    return {"count": len(summaries), "experiences": summaries}
