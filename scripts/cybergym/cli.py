"""F86 — CyberGym benchmark CLI.

Usage:
  python -m scripts.cybergym --task arvo-47101                # single
  python -m scripts.cybergym --all                            # full subset
  python -m scripts.cybergym --all --status ready
  python -m scripts.cybergym --subset 30 --out reports/cg.json --html reports/cg.html
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from scripts.cybergym.loader import TaskInvalid, load_subset, load_walkthrough
from scripts.cybergym.runner import RunResult, run_task
from scripts.cybergym.scorer import aggregate

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BENCH_ROOT = _REPO_ROOT / "tests" / "benchmarks" / "cybergym"


def _resolve_walkthrough(slug: str) -> Path:
    return _BENCH_ROOT / "tasks" / f"{slug}.json"


def _select_tasks(args: argparse.Namespace) -> list[str]:
    """Apply --task / --all / --status / --subset filters."""
    if args.task:
        return [args.task]

    subset_name = f"subset_{args.subset}.yaml" if args.subset else "subset_30.yaml"
    manifest_path = _BENCH_ROOT / subset_name
    if not manifest_path.exists():
        print(f"No subset manifest at {manifest_path}", file=sys.stderr)
        return []
    tasks = load_subset(manifest_path)

    selected: list[str] = []
    for entry in tasks:
        if args.status and entry.get("status") != args.status:
            continue
        if not args.status and not args.all:
            # No selector → only `status: ready` (matches htb_bench default).
            if entry.get("status") != "ready":
                continue
        selected.append(entry["slug"])
    return selected


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="F86 CyberGym vuln-hunter benchmark")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--task", help="single task slug to run")
    g.add_argument("--all", action="store_true", help="run every task in the subset")
    ap.add_argument(
        "--subset",
        default="30",
        help="subset name (resolves to subset_<NAME>.yaml; default: 30)",
    )
    ap.add_argument(
        "--status",
        choices=["ready", "wip", "planned"],
        help="when --all, restrict to this status (default: ready)",
    )
    ap.add_argument(
        "--out",
        default="reports/cybergym.json",
        help="path to write aggregated JSON report",
    )
    ap.add_argument(
        "--html",
        help="path to ALSO write a static HTML scoreboard (reuses F83 reporter)",
    )
    args = ap.parse_args(argv)

    slugs = _select_tasks(args)
    if not slugs:
        print("No tasks selected. Use --all or --task <slug>.", file=sys.stderr)
        return 2

    results: list[RunResult] = []
    tasks_meta: dict[str, dict[str, Any]] = {}

    for slug in slugs:
        wt_path = _resolve_walkthrough(slug)
        if not wt_path.exists():
            print(f"  [SKIP] {slug} — no walkthrough JSON at {wt_path}", file=sys.stderr)
            continue
        try:
            wt = load_walkthrough(wt_path)
        except TaskInvalid as e:
            print(f"  [SKIP] {slug} — {e}", file=sys.stderr)
            continue
        tasks_meta[slug] = wt
        print(f"  [RUN ] {slug} ...", flush=True)
        result = run_task(wt_path)
        results.append(result)
        status = "OK  " if result.detected else ("ERR " if result.error else "FAIL")
        print(f"  [{status}] {slug}  {result.wall_time_seconds:.1f}s", flush=True)

    report = aggregate(results, tasks_meta)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "report": asdict(report),
        "results": [asdict(r) for r in results],
        "subset": args.subset,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.html:
        # Dedicated F86 reporter — sibling of F83 but with detection
        # vocabulary (DETECT/CWE/FILE/MISS) and Wilson 95% LB front
        # and centre.
        from scripts.cybergym.reporter import write_report

        html_path = write_report(payload, Path(args.html))
        print(f"  HTML  -> {html_path}", flush=True)

    print()
    print(
        f"  Total: {report.total_tasks}  "
        f"Detected: {report.detected}  "
        f"Rate: {report.detection_rate * 100:.1f}%  "
        f"Wilson95: {report.wilson_lower_95 * 100:.1f}%  "
        f"FPR: {report.false_positive_rate * 100:.1f}%  "
        f"Errors: {report.errors}"
    )
    print(f"  Report -> {out_path}")

    return 0 if report.errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
