"""F8.2 — bootstrap confidence intervals over bench recall@CWE.

Reads a bench JSON produced by scripts/bench_juliet.py (with F8.2
per_file_* arrays) and computes:

  - Point recall@CWE per (runner, CWE).
  - Bootstrap 95% CI (percentile, 2000 resamples).
  - Pairwise CI overlap check between two configs so we can tell
    whether the F8.1.b fix is statistically distinguishable from
    the pre-fix baseline.

Usage:
  python bootstrap_ci.py --prefix pre.json --postfix post.json \
      --label-a hybrid-pre --label-b hybrid-post
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path


def bootstrap_ci(labels: list[int], n_resamples: int = 2000,
                 alpha: float = 0.05, seed: int = 42) -> tuple[float, float, float]:
    """Percentile bootstrap CI for a binomial proportion.
    Returns (point_estimate, lower, upper)."""
    if not labels:
        return (0.0, 0.0, 0.0)
    rng = random.Random(seed)
    n = len(labels)
    point = sum(labels) / n
    samples = []
    for _ in range(n_resamples):
        idx = [rng.randrange(n) for _ in range(n)]
        samples.append(sum(labels[i] for i in idx) / n)
    samples.sort()
    lo = samples[int(n_resamples * alpha / 2)]
    hi = samples[int(n_resamples * (1 - alpha / 2)) - 1]
    return (point, lo, hi)


def overlapping(a: tuple[float, float, float], b: tuple[float, float, float]) -> bool:
    """True if the two CIs overlap — meaning the difference is NOT
    statistically significant at the alpha used for the bootstrap."""
    return not (a[2] < b[1] or b[2] < a[1])


def summarise(path: Path, runner: str) -> dict:
    """Return {cwe: (point, lo, hi)} for recall@CWE across all CWEs
    plus an overall pooled estimate."""
    doc = json.loads(path.read_text())
    results: dict = {}
    all_labels: list[int] = []
    for row in doc["recall"]:
        per = (row.get("per_runner") or {}).get(runner)
        if not per:
            continue
        labels = per.get("per_file_cwe_matched") or []
        results[row["cwe"]] = bootstrap_ci(labels)
        all_labels.extend(labels)
    results["_pooled"] = bootstrap_ci(all_labels)
    results["_n_files"] = len(all_labels)
    return results


def render(label: str, summary: dict) -> str:
    lines = [f"=== {label} (n_files={summary.get('_n_files', '?')}) ==="]
    for cwe in sorted(k for k in summary if isinstance(k, int)):
        p, lo, hi = summary[cwe]
        lines.append(
            f"  CWE-{cwe:<4} recall@CWE = {p*100:5.1f}%  "
            f"95% CI [{lo*100:5.1f}, {hi*100:5.1f}]"
        )
    p, lo, hi = summary["_pooled"]
    lines.append(
        f"  pooled     recall@CWE = {p*100:5.1f}%  "
        f"95% CI [{lo*100:5.1f}, {hi*100:5.1f}]"
    )
    return "\n".join(lines)


def compare(label_a: str, sum_a: dict, label_b: str, sum_b: dict) -> str:
    lines = [f"=== pairwise CI check: {label_a} vs {label_b} ==="]
    cwes = sorted({k for k in sum_a if isinstance(k, int)} |
                  {k for k in sum_b if isinstance(k, int)})
    for cwe in cwes:
        a = sum_a.get(cwe)
        b = sum_b.get(cwe)
        if a is None or b is None:
            continue
        overlap = overlapping(a, b)
        delta = (b[0] - a[0]) * 100
        verdict = "OVERLAP — not significant" if overlap else "DISTINCT — significant"
        lines.append(
            f"  CWE-{cwe:<4} Δ={delta:+5.1f}pp  "
            f"{label_a}={a[0]*100:5.1f}% CI [{a[1]*100:5.1f},{a[2]*100:5.1f}]  "
            f"{label_b}={b[0]*100:5.1f}% CI [{b[1]*100:5.1f},{b[2]*100:5.1f}]  "
            f"{verdict}"
        )
    a = sum_a["_pooled"]
    b = sum_b["_pooled"]
    overlap = overlapping(a, b)
    delta = (b[0] - a[0]) * 100
    verdict = "OVERLAP" if overlap else "DISTINCT"
    lines.append(
        f"  pooled     Δ={delta:+5.1f}pp  "
        f"{label_a}={a[0]*100:5.1f}% CI [{a[1]*100:5.1f},{a[2]*100:5.1f}]  "
        f"{label_b}={b[0]*100:5.1f}% CI [{b[1]*100:5.1f},{b[2]*100:5.1f}]  "
        f"{verdict}"
    )
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pre", required=True, help="bench JSON pre-fix")
    p.add_argument("--post", required=True, help="bench JSON post-fix")
    p.add_argument("--runner", default="hybrid")
    p.add_argument("--label-pre", default="pre-F8.1.b")
    p.add_argument("--label-post", default="post-F8.1.b")
    a = p.parse_args()

    sum_pre = summarise(Path(a.pre), a.runner)
    sum_post = summarise(Path(a.post), a.runner)
    print(render(a.label_pre, sum_pre))
    print()
    print(render(a.label_post, sum_post))
    print()
    print(compare(a.label_pre, sum_pre, a.label_post, sum_post))


if __name__ == "__main__":
    main()
