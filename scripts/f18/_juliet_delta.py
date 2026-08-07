"""Juliet bench delta analyzer — compare two bench JSON files.

Usage:
    python scripts/f18/_juliet_delta.py <baseline.json> <new.json>

Produces a markdown-ready table with:
  - Pooled recall delta per runner
  - Per-CWE recall delta per runner (hybrid in particular)
  - FPR proxy delta per runner
  - Duration delta

Designed for post-F75 comparison against baseline_pre_f75.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _pooled(recall_rows: list[dict]) -> dict[str, dict[str, float]]:
    """Sum per-runner any/cwe hits across all CWEs."""
    out: dict[str, dict[str, float]] = {}
    for row in recall_rows:
        for runner, stats in row["per_runner"].items():
            acc = out.setdefault(runner, {"total": 0, "any": 0, "cwe": 0})
            acc["total"] += stats["n_files"]
            acc["any"] += stats.get("any_finding", 0)
            acc["cwe"] += stats.get("cwe_matched", 0)
    return out


def _per_cwe(recall_rows: list[dict]) -> dict[tuple[int, str], dict[str, float]]:
    """Index (cwe, runner) → {recall_any, recall_cwe_match}."""
    idx: dict[tuple[int, str], dict[str, float]] = {}
    for row in recall_rows:
        cwe = row["cwe"]
        for runner, stats in row["per_runner"].items():
            idx[(cwe, runner)] = {
                "recall_any": stats.get("recall_any", 0) * 100,
                "recall_cwe": stats.get("recall_cwe_match", 0) * 100,
            }
    return idx


def fmt_delta(old: float, new: float, precision: int = 1) -> str:
    d = new - old
    sign = "+" if d > 0 else ""
    return f"{new:.{precision}f}% ({sign}{d:.{precision}f})"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline", help="baseline bench JSON path")
    ap.add_argument("new", help="new bench JSON path")
    ap.add_argument("--md", action="store_true", help="Output markdown only")
    args = ap.parse_args()

    base = load(args.baseline)
    new = load(args.new)

    base_pooled = _pooled(base["recall"])
    new_pooled = _pooled(new["recall"])
    base_per_cwe = _per_cwe(base["recall"])
    new_per_cwe = _per_cwe(new["recall"])

    lines: list[str] = []

    # Header
    lines.append("## Pooled recall (7 CWE × N=100 = 700 samples)\n")
    lines.append("| Runner | Baseline recall@CWE | New recall@CWE | Delta recall@any | Delta recall@CWE |")
    lines.append("|---|---|---|---|---|")

    all_runners = sorted(set(base_pooled) | set(new_pooled))
    for runner in all_runners:
        b = base_pooled.get(runner, {"total": 0, "any": 0, "cwe": 0})
        n = new_pooled.get(runner, {"total": 0, "any": 0, "cwe": 0})
        b_any = b["any"] / max(1, b["total"]) * 100
        n_any = n["any"] / max(1, n["total"]) * 100
        b_cwe = b["cwe"] / max(1, b["total"]) * 100
        n_cwe = n["cwe"] / max(1, n["total"]) * 100
        if b["total"] == 0:
            base_cell = "— (new)"
            any_d = f"{n_any:.1f}%"
            cwe_d = f"{n_cwe:.1f}%"
        else:
            base_cell = f"{b_cwe:.1f}%"
            any_d = fmt_delta(b_any, n_any)
            cwe_d = fmt_delta(b_cwe, n_cwe)
        if n["total"] == 0:
            new_cell = "—"
        else:
            new_cell = f"{n_cwe:.1f}%"
        lines.append(f"| {runner} | {base_cell} | {new_cell} | {any_d} | {cwe_d} |")

    lines.append("")
    lines.append("## FPR proxy")
    lines.append("")
    lines.append(
        f"Baseline repo: `{base.get('baseline_repo','?')}` "
        f"({base.get('baseline_files_scanned', '?')} files)"
    )
    lines.append(
        f"New repo: `{new.get('baseline_repo','?')}` "
        f"({new.get('baseline_files_scanned', '?')} files)"
    )
    lines.append("")
    lines.append("| Runner | Baseline FPR | New FPR | Delta FPR |")
    lines.append("|---|---|---|---|")
    all_fpr_runners = sorted(
        set(base.get("fpr", {})) | set(new.get("fpr", {}))
    )
    for runner in all_fpr_runners:
        bf = base.get("fpr", {}).get(runner)
        nf = new.get("fpr", {}).get(runner)
        if not isinstance(bf, dict) or not isinstance(nf, dict):
            if isinstance(nf, dict):
                nf_rate = nf["fpr_proxy"] * 100
                lines.append(f"| {runner} | — (new) | {nf_rate:.1f}% | — |")
            continue
        b_rate = bf["fpr_proxy"] * 100
        n_rate = nf["fpr_proxy"] * 100
        lines.append(
            f"| {runner} | {b_rate:.1f}% | {n_rate:.1f}% | "
            f"{fmt_delta(b_rate, n_rate)} |"
        )

    lines.append("")
    lines.append("## Per-CWE recall@CWE (all runners)")
    lines.append("")

    # Collect every CWE seen in either bench
    all_cwes = sorted({c for (c, _) in base_per_cwe} | {c for (c, _) in new_per_cwe})
    for cwe in all_cwes:
        lines.append(f"### CWE-{cwe}")
        lines.append("")
        lines.append("| Runner | Baseline | New | Delta |")
        lines.append("|---|---|---|---|")
        for runner in all_runners:
            b_stats = base_per_cwe.get((cwe, runner))
            n_stats = new_per_cwe.get((cwe, runner))
            if n_stats is None:
                continue
            if b_stats is None:
                lines.append(
                    f"| {runner} | — (new) | {n_stats['recall_cwe']:.1f}% | — |"
                )
                continue
            b_val = b_stats["recall_cwe"]
            n_val = n_stats["recall_cwe"]
            lines.append(
                f"| {runner} | {b_val:.1f}% | {n_val:.1f}% | "
                f"{fmt_delta(b_val, n_val)} |"
            )
        lines.append("")

    # Duration
    lines.append(
        f"## Duration\n\n- Baseline: {base.get('duration_s', 0):.1f}s\n"
        f"- New: {new.get('duration_s', 0):.1f}s"
    )

    output = "\n".join(lines)
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
