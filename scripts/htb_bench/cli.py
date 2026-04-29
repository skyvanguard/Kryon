"""F81 — CLI entry point.

Usage:
  python -m scripts.htb_bench --target dvwa-sqli-low
  python -m scripts.htb_bench --all
  python -m scripts.htb_bench --status ready --out reports/htb_2026-04-29.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

from scripts.htb_bench.runner import RunResult, load_walkthrough, run_target
from scripts.htb_bench.scorer import aggregate

_REPO_ROOT = Path(__file__).resolve().parents[2]
_LABSET = _REPO_ROOT / "tests" / "benchmarks" / "htb_style" / "labset.yaml"
_WALKTHROUGHS = _REPO_ROOT / "tests" / "benchmarks" / "htb_style" / "walkthroughs"


def _load_labset() -> dict[str, Any]:
    return yaml.safe_load(_LABSET.read_text(encoding="utf-8"))


def _select_targets(args: argparse.Namespace) -> list[str]:
    """Apply --target / --all / --status filters → ordered slug list."""
    labset = _load_labset()
    all_targets = labset.get("targets", [])

    if args.target:
        # Explicit single target. Skip status check — caller knows.
        return [args.target]

    if args.all:
        slugs = [t["slug"] for t in all_targets]
        if args.status:
            slugs = [
                t["slug"] for t in all_targets if t.get("status") == args.status
            ]
        return slugs

    # No selector — default: only `status: ready`.
    return [t["slug"] for t in all_targets if t.get("status") == "ready"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="F81 HTB-style benchmark harness")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--target", help="single target slug to run")
    g.add_argument("--all", action="store_true", help="run every target in the labset")
    ap.add_argument(
        "--status",
        choices=["ready", "wip", "planned"],
        help="when --all, restrict to this status (default: ready)",
    )
    ap.add_argument(
        "--out",
        default="reports/htb_bench.json",
        help="path to write aggregated JSON report",
    )
    args = ap.parse_args(argv)

    slugs = _select_targets(args)
    if not slugs:
        print("No targets selected. Use --all or --target <slug>.", file=sys.stderr)
        return 2

    results: list[RunResult] = []
    walkthroughs: dict[str, dict[str, Any]] = {}

    for slug in slugs:
        wt_path = _WALKTHROUGHS / f"{slug}.json"
        if not wt_path.exists():
            print(f"  [SKIP] {slug} — no walkthrough JSON", file=sys.stderr)
            continue

        try:
            wt = load_walkthrough(wt_path)
        except Exception as e:
            print(f"  [SKIP] {slug} — walkthrough invalid: {e}", file=sys.stderr)
            continue

        walkthroughs[slug] = wt

        print(f"  [RUN ] {slug} …", flush=True)
        result = run_target(wt_path)
        results.append(result)

        status = "PWN " if result.pwn else "FAIL"
        if result.error:
            status = "ERR "
        elapsed = f"{result.wall_time_seconds:.1f}s"
        print(f"  [{status}] {slug}  {elapsed}", flush=True)

    report = aggregate(results, walkthroughs)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "report": asdict(report),
        "results": [asdict(r) for r in results],
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print()
    print(f"  Total: {report.total_targets}  Pwned: {report.pwned}  "
          f"Rate: {report.pwn_rate * 100:.1f}%  Errors: {report.errors}")
    print(f"  Report -> {out_path}")

    return 0 if report.errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
