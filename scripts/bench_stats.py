"""F190 — Statistical summary over scripts/bench_results.csv.

Reads the bench results, filters by an optional ``--engagement-prefix``
or ``--last-n``, and prints mean/stddev/min/max/CI95 for findings count
and wall-clock, plus the SATISFIED/PARTIAL/NOT_MET breakdown.

Usage:
    python scripts/bench_stats.py
    python scripts/bench_stats.py --last-n 20
    python scripts/bench_stats.py --engagement-prefix bench-kryon_gpt_oss-juice_shop-f190
    python scripts/bench_stats.py --json   # machine-readable

The script is pure-stdlib (csv + statistics + argparse) so it runs in
any Kryon environment without extra deps.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
from pathlib import Path


def _t_value_95(df: int) -> float:
    """Return the two-tailed t-value at 95% confidence for ``df`` degrees
    of freedom. Hardcoded table for common small samples; falls back to
    1.96 (normal approximation) for df > 30."""
    table = {
        1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
        6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
        11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
        16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
        21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
        26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
    }
    if df in table:
        return table[df]
    if df < 1:
        return float("nan")
    return 1.96


def _ci_95(values: list[float]) -> tuple[float, float, float]:
    """Return ``(mean, half_width, n)`` for a 95% confidence interval.

    Uses the t-distribution for n < 30, normal for n >= 30.
    """
    n = len(values)
    if n == 0:
        return float("nan"), float("nan"), 0
    if n == 1:
        return float(values[0]), float("nan"), 1
    mean = statistics.mean(values)
    stdev = statistics.stdev(values)
    t = _t_value_95(n - 1)
    half = t * stdev / math.sqrt(n)
    return mean, half, n


def _summarize(rows: list[dict]) -> dict:
    findings = [int(r["findings"]) for r in rows if r.get("findings", "").isdigit()]
    cves = [int(r["cve_count_in_findings"]) for r in rows if r.get("cve_count_in_findings", "").isdigit()]
    walls = [int(r["wall_clock_s"]) for r in rows if r.get("wall_clock_s", "").isdigit()]
    verdicts = [r.get("verdict", "") or "EMPTY" for r in rows]

    verdict_counts: dict[str, int] = {}
    for v in verdicts:
        verdict_counts[v] = verdict_counts.get(v, 0) + 1

    f_mean, f_half, f_n = _ci_95([float(x) for x in findings])
    w_mean, w_half, _ = _ci_95([float(x) for x in walls])

    return {
        "n": len(rows),
        "findings": {
            "n": f_n,
            "mean": round(f_mean, 2),
            "stddev": round(statistics.stdev(findings), 2) if len(findings) >= 2 else 0.0,
            "min": min(findings) if findings else 0,
            "max": max(findings) if findings else 0,
            "median": round(statistics.median(findings), 2) if findings else 0,
            "ci_95_half_width": round(f_half, 2) if not math.isnan(f_half) else None,
            "ci_95_lower": round(f_mean - f_half, 2) if not math.isnan(f_half) else None,
            "ci_95_upper": round(f_mean + f_half, 2) if not math.isnan(f_half) else None,
        },
        "wall_clock_s": {
            "mean": round(w_mean, 1),
            "min": min(walls) if walls else 0,
            "max": max(walls) if walls else 0,
            "median": round(statistics.median(walls), 1) if walls else 0,
            "ci_95_half_width": round(w_half, 1) if not math.isnan(w_half) else None,
        },
        "cves_in_findings": {
            "mean": round(statistics.mean(cves), 2) if cves else 0.0,
            "total": sum(cves),
            "any_with_cve": sum(1 for c in cves if c > 0),
        },
        "verdicts": verdict_counts,
        "satisfied_rate": round(
            verdict_counts.get("SATISFIED", 0) / max(len(rows), 1), 3
        ),
    }


def _filter(
    csv_path: Path,
    *,
    engagement_prefix: str | None,
    model: str | None,
    target: str | None,
    last_n: int | None,
) -> list[dict]:
    with csv_path.open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    if engagement_prefix:
        rows = [r for r in rows if r.get("engagement_id", "").startswith(engagement_prefix)]
    if model:
        rows = [r for r in rows if r.get("model") == model]
    if target:
        rows = [r for r in rows if r.get("target") == target]
    if last_n:
        rows = rows[-last_n:]
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--csv",
        default=str(Path(__file__).parent / "bench_results.csv"),
        help="Path to bench_results.csv",
    )
    parser.add_argument(
        "--engagement-prefix",
        default=None,
        help="Only include rows whose engagement_id starts with this prefix",
    )
    parser.add_argument("--model", default=None)
    parser.add_argument("--target", default=None)
    parser.add_argument("--last-n", type=int, default=None)
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON instead of text"
    )
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"ERROR: CSV not found at {csv_path}", file=sys.stderr)
        return 2

    rows = _filter(
        csv_path,
        engagement_prefix=args.engagement_prefix,
        model=args.model,
        target=args.target,
        last_n=args.last_n,
    )
    if not rows:
        print("No rows match the filter — nothing to summarize", file=sys.stderr)
        return 1

    summary = _summarize(rows)

    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    f = summary["findings"]
    w = summary["wall_clock_s"]
    print(f"=== Bench summary over n={summary['n']} runs ===")
    print()
    print(f"Findings: mean={f['mean']:.2f}  stddev={f['stddev']:.2f}  "
          f"median={f['median']:.2f}  min={f['min']}  max={f['max']}")
    if f["ci_95_half_width"] is not None:
        print(f"          95% CI: [{f['ci_95_lower']:.2f}, {f['ci_95_upper']:.2f}] "
              f"(± {f['ci_95_half_width']:.2f})")
    print()
    print(f"Wall:     mean={w['mean']:.1f}s  median={w['median']:.1f}s  "
          f"min={w['min']}s  max={w['max']}s")
    if w["ci_95_half_width"] is not None:
        print(f"          95% CI: ± {w['ci_95_half_width']:.1f}s")
    print()
    print(f"CVEs in findings: total={summary['cves_in_findings']['total']}  "
          f"runs_with_cve={summary['cves_in_findings']['any_with_cve']}/{summary['n']}")
    print()
    print(f"Verdict breakdown: {summary['verdicts']}")
    print(f"SATISFIED rate: {summary['satisfied_rate']:.1%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
