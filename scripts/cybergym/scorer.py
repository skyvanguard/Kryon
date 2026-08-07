"""F86 — Aggregate per-task results into labset-wide metrics.

Adds two metrics on top of the HTB scorer:

  * Detection rate with **Wilson 95% lower bound** — matches F77.G F2
    skill scoring so a single benchmark can be compared apples-to-
    apples against learning-loop telemetry. Wilson is preferred over
    naive p̂ for small n because it never collapses to 0 or 1, and
    it's the same statistic Kryon uses internally to rank skills.
  * False positive rate — defined as "agent named a CWE that does not
    match the expected one". Because CyberGym tasks are
    single-vulnerability, any extra CWE finding counts as a false
    positive contributing to FPR.

Pure data — no I/O, no formatting.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from scripts.cybergym.runner import RunResult


@dataclass(frozen=True)
class BenchmarkReport:
    """Aggregated metrics over a CyberGym subset run."""

    total_tasks: int
    detected: int
    detection_rate: float           # 0..1, point estimate
    wilson_lower_95: float          # 0..1, lower bound at 95% confidence
    cwe_only_rate: float            # CWE matched but file did not
    file_only_rate: float           # file matched but CWE did not
    false_positive_rate: float      # 0..1
    median_wall_seconds: float | None
    by_category: dict[str, dict[str, float]] = field(default_factory=dict)
    errors: int = 0
    error_breakdown: dict[str, int] = field(default_factory=dict)


def wilson_lower_bound(successes: int, total: int, z: float = 1.96) -> float:
    """Wilson score interval, lower bound. z=1.96 ≈ 95% CI.

    Matches the implementation in src/kryon/learning/skill_scorer.py
    so the same number means the same thing on both surfaces.
    Returns 0.0 when total is 0 (no observations → no confidence)."""
    if total <= 0:
        return 0.0
    phat = successes / total
    denom = 1 + z * z / total
    centre = phat + z * z / (2 * total)
    margin = z * math.sqrt(phat * (1 - phat) / total + z * z / (4 * total * total))
    return max(0.0, (centre - margin) / denom)


def aggregate(
    results: list[RunResult],
    tasks: dict[str, dict[str, Any]],  # slug -> task dict from manifest
) -> BenchmarkReport:
    """Roll up a list of `RunResult` + their manifest entries into a
    `BenchmarkReport`."""
    total = len(results)
    detected = sum(1 for r in results if r.detected)
    detection_rate = detected / total if total else 0.0

    # CWE / file partial-credit rates.
    cwe_only = sum(1 for r in results if r.cwe_match and not r.file_match)
    file_only = sum(1 for r in results if r.file_match and not r.cwe_match)
    cwe_only_rate = cwe_only / total if total else 0.0
    file_only_rate = file_only / total if total else 0.0

    # False positive: agent named a CWE that does NOT match expected.
    fp_count = 0
    for r in results:
        expected_num = r.expected_cwe.replace("CWE-", "").strip()
        extras = [c for c in r.actual_cwes_found if c.split("-")[-1] != expected_num]
        if extras:
            fp_count += 1
    fpr = fp_count / total if total else 0.0

    # Median wall time across ALL runs (not just detected) so a
    # slow-but-correct agent doesn't hide behind a fast-and-wrong run.
    walls = [r.wall_time_seconds for r in results if r.wall_time_seconds > 0]
    median_wall = statistics.median(walls) if walls else None

    # Per-category breakdown.
    by_cat: dict[str, list[RunResult]] = defaultdict(list)
    for r in results:
        cat = tasks.get(r.slug, {}).get("category", "unknown")
        by_cat[cat].append(r)
    by_category_metrics = {}
    for cat, rs in by_cat.items():
        cat_detected = sum(1 for r in rs if r.detected)
        by_category_metrics[cat] = {
            "total": float(len(rs)),
            "detected": float(cat_detected),
            "detection_rate": cat_detected / len(rs) if rs else 0.0,
            "wilson_lower_95": wilson_lower_bound(cat_detected, len(rs)),
        }

    # Error breakdown.
    err_counts: dict[str, int] = defaultdict(int)
    for r in results:
        if r.error:
            key = r.error.split(":", 1)[0]
            err_counts[key] += 1
    errors_total = sum(err_counts.values())

    return BenchmarkReport(
        total_tasks=total,
        detected=detected,
        detection_rate=detection_rate,
        wilson_lower_95=wilson_lower_bound(detected, total),
        cwe_only_rate=cwe_only_rate,
        file_only_rate=file_only_rate,
        false_positive_rate=fpr,
        median_wall_seconds=median_wall,
        by_category=by_category_metrics,
        errors=errors_total,
        error_breakdown=dict(err_counts),
    )
