"""F81 — Aggregate per-target results into labset-wide metrics.

Produces a `BenchmarkReport` (frozen dataclass) consumed by the
reporter. Pure data — no I/O, no formatting. Re-run safe.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from scripts.htb_bench.runner import RunResult


@dataclass(frozen=True)
class BenchmarkReport:
    """Aggregated metrics across a labset run."""

    total_targets: int
    pwned: int
    pwn_rate: float  # 0..1
    mean_chain_match: float  # over pwned targets only; 0..1
    median_time_to_pwn_seconds: float | None
    by_category: dict[str, dict[str, float]] = field(default_factory=dict)
    errors: int = 0
    error_breakdown: dict[str, int] = field(default_factory=dict)


def aggregate(
    results: list[RunResult],
    walkthroughs: dict[str, dict[str, Any]],  # slug -> walkthrough dict
) -> BenchmarkReport:
    """Roll up a list of `RunResult` plus their source walkthroughs into
    a `BenchmarkReport`. `walkthroughs` is keyed by slug so we can pull
    `category` for grouping.
    """
    total = len(results)
    pwned_results = [r for r in results if r.pwn]
    pwned = len(pwned_results)

    pwn_rate = pwned / total if total else 0.0

    chain_scores = [r.chain_match_score for r in pwned_results]
    mean_chain = statistics.fmean(chain_scores) if chain_scores else 0.0

    times = [r.time_to_pwn_seconds for r in pwned_results if r.time_to_pwn_seconds is not None]
    median_time = statistics.median(times) if times else None

    # Per-category metrics.
    by_cat: dict[str, list[RunResult]] = defaultdict(list)
    for r in results:
        cat = walkthroughs.get(r.slug, {}).get("category", "unknown")
        by_cat[cat].append(r)

    by_category_metrics = {}
    for cat, rs in by_cat.items():
        cat_pwned = sum(1 for r in rs if r.pwn)
        by_category_metrics[cat] = {
            "total": float(len(rs)),
            "pwned": float(cat_pwned),
            "pwn_rate": cat_pwned / len(rs) if rs else 0.0,
        }

    # Error breakdown — what failed and how often.
    err_counts: dict[str, int] = defaultdict(int)
    for r in results:
        if r.error:
            # Coalesce by error class prefix (drop the message tail).
            key = r.error.split(":", 1)[0]
            err_counts[key] += 1

    errors_total = sum(err_counts.values())

    return BenchmarkReport(
        total_targets=total,
        pwned=pwned,
        pwn_rate=pwn_rate,
        mean_chain_match=mean_chain,
        median_time_to_pwn_seconds=median_time,
        by_category=by_category_metrics,
        errors=errors_total,
        error_breakdown=dict(err_counts),
    )
