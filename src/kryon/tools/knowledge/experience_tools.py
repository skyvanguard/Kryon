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
