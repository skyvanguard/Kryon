"""F90.1 — agent-facing tool wrapper for the typosquat generator.

Two operation shapes:
  - mode="generate" — pure generation, no I/O. Returns the candidate
    list. Useful for the operator to review before approving live
    DNS scans.
  - mode="scan" — generate + DNS-resolve each candidate under the
    double gate. Returns the per-candidate verdicts plus a summary.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from kryon.brand.typosquat import (
    DEFAULT_MAX_VARIANTS,
    ALL_STRATEGIES,
    TyposquatScanResult,
    generate_typosquats,
    resolve_candidate,
)
from kryon.sdk.agents import function_tool

__all__ = ["typosquat_scan"]


def _scan_summary(results: list[TyposquatScanResult]) -> dict[str, Any]:
    by_verdict: dict[str, int] = {}
    by_strategy: dict[str, int] = {}
    registered: list[dict[str, Any]] = []
    for r in results:
        by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        s = r.candidate.strategy
        by_strategy[s] = by_strategy.get(s, 0) + 1
        if r.verdict == "registered":
            registered.append(
                {
                    "variant": r.candidate.variant,
                    "display": r.candidate.display_variant,
                    "strategy": s,
                    "ips": list(r.ip_addresses),
                }
            )
    return {
        "total_candidates": len(results),
        "by_verdict": by_verdict,
        "by_strategy": by_strategy,
        "registered_count": len(registered),
        "registered": registered,
    }


@function_tool
def typosquat_scan(
    domain: str,
    mode: str = "generate",
    fire: bool = False,
    max_variants: int = DEFAULT_MAX_VARIANTS,
    strategies_csv: str = "",
) -> str:
    """Generate (and optionally DNS-scan) typosquat variants.

    Args:
        domain: target domain (e.g. "bcp.com.py").
        mode: "generate" (default) returns the candidate list only —
            no network I/O. "scan" runs DNS lookups under the double
            gate (KRYON_BRAND_FIRE=true env + fire=True).
        fire: required (with env) for live DNS in scan mode. Ignored
            in generate mode.
        max_variants: cap on candidates returned / scanned.
        strategies_csv: comma-separated subset of the 7 strategies
            to run. Empty = all. Example: "transposition,omission".

    Returns:
        JSON string. Generate mode: {candidates: [{...}, ...]}.
        Scan mode: {summary: {...}, results: [{...}, ...]}.
    """
    if not domain.strip():
        return json.dumps({"error": "empty domain"})
    if mode not in ("generate", "scan"):
        return json.dumps({"error": f"unknown mode {mode!r}; use generate or scan"})

    strategies = None
    if strategies_csv.strip():
        requested = tuple(s.strip() for s in strategies_csv.split(",") if s.strip())
        invalid = [s for s in requested if s not in ALL_STRATEGIES]
        if invalid:
            return json.dumps({"error": f"unknown strategies: {invalid}"})
        strategies = requested

    candidates = generate_typosquats(
        domain,
        max_variants=max_variants,
        strategies=strategies,
    )

    if mode == "generate":
        return json.dumps(
            {
                "domain": domain,
                "candidate_count": len(candidates),
                "candidates": [
                    {
                        "variant": c.variant,
                        "display": c.display_variant,
                        "strategy": c.strategy,
                    }
                    for c in candidates
                ],
            },
            ensure_ascii=False,
        )

    # scan
    results = [resolve_candidate(c, fire=fire) for c in candidates]
    return json.dumps(
        {
            "domain": domain,
            "summary": _scan_summary(results),
            "results": [
                {
                    "variant": r.candidate.variant,
                    "display": r.candidate.display_variant,
                    "strategy": r.candidate.strategy,
                    "verdict": r.verdict,
                    "ips": list(r.ip_addresses),
                    "error": r.error,
                }
                for r in results
            ],
        },
        ensure_ascii=False,
    )
