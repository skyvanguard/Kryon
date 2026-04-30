"""F81/F82 — CLI entry point (platform-agnostic).

Usage:
  python -m scripts.htb_bench --target dvwa-sqli-low                         # auto-detect platform
  python -m scripts.htb_bench --platform htb --all
  python -m scripts.htb_bench --platform tryhackme --all
  python -m scripts.htb_bench --platform all --status ready --out reports/r.json
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
_BENCH_ROOT = _REPO_ROOT / "tests" / "benchmarks"

# Each platform has the same shape: <root>/<platform>/labset.yaml + walkthroughs/.
# Add a new entry here and the harness picks it up — no code change needed.
PLATFORMS: dict[str, dict[str, Path]] = {
    "htb": {
        "labset":       _BENCH_ROOT / "htb_style" / "labset.yaml",
        "walkthroughs": _BENCH_ROOT / "htb_style" / "walkthroughs",
    },
    "tryhackme": {
        "labset":       _BENCH_ROOT / "tryhackme" / "labset.yaml",
        "walkthroughs": _BENCH_ROOT / "tryhackme" / "walkthroughs",
    },
}


def _load_labset_for(platform: str) -> dict[str, Any]:
    return yaml.safe_load(PLATFORMS[platform]["labset"].read_text(encoding="utf-8"))


def _resolve_walkthrough(slug: str, platform: str | None) -> tuple[Path, str]:
    """Locate a walkthrough JSON. When `platform` is None, search every
    configured platform — the first match wins. Returns (path, platform).
    """
    if platform and platform != "all":
        return PLATFORMS[platform]["walkthroughs"] / f"{slug}.json", platform

    # `--platform all` or unspecified: search across platforms.
    for plat, paths in PLATFORMS.items():
        candidate = paths["walkthroughs"] / f"{slug}.json"
        if candidate.exists():
            return candidate, plat
    # Default to htb so the error message points somewhere consistent.
    return PLATFORMS["htb"]["walkthroughs"] / f"{slug}.json", "htb"


def _select_targets(args: argparse.Namespace) -> list[tuple[str, str]]:
    """Apply --target / --all / --status / --platform filters.
    Returns a list of (slug, platform) tuples in display order."""
    if args.target:
        # Explicit single slug. Resolve platform from filename.
        _, plat = _resolve_walkthrough(args.target, args.platform)
        return [(args.target, plat)]

    platforms = (
        list(PLATFORMS.keys())
        if (args.platform in (None, "all"))
        else [args.platform]
    )

    selected: list[tuple[str, str]] = []
    for plat in platforms:
        labset = _load_labset_for(plat)
        for entry in labset.get("targets", []):
            if args.status and entry.get("status") != args.status:
                continue
            if not args.status and not args.all:
                # No selector → only `status: ready` (legacy default).
                if entry.get("status") != "ready":
                    continue
            selected.append((entry["slug"], plat))
    return selected


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="F81/F82 lab benchmark harness")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--target", help="single target slug to run")
    g.add_argument("--all", action="store_true", help="run every target in the selected platform(s)")
    ap.add_argument(
        "--platform",
        choices=["htb", "tryhackme", "all"],
        help="which labset(s) to draw from (default: all when --all is used)",
    )
    ap.add_argument(
        "--status",
        choices=["ready", "wip", "planned"],
        help="when --all, restrict to this status (default: ready)",
    )
    ap.add_argument(
        "--out",
        default="reports/bench.json",
        help="path to write aggregated JSON report",
    )
    args = ap.parse_args(argv)

    pairs = _select_targets(args)
    if not pairs:
        print("No targets selected. Use --all or --target <slug>.", file=sys.stderr)
        return 2

    results: list[RunResult] = []
    walkthroughs: dict[str, dict[str, Any]] = {}

    for slug, platform in pairs:
        wt_path, _ = _resolve_walkthrough(slug, platform)
        if not wt_path.exists():
            print(f"  [SKIP] {slug} ({platform}) — no walkthrough JSON", file=sys.stderr)
            continue

        try:
            wt = load_walkthrough(wt_path)
        except Exception as e:
            print(f"  [SKIP] {slug} — walkthrough invalid: {e}", file=sys.stderr)
            continue

        walkthroughs[slug] = wt

        print(f"  [RUN ] {platform}/{slug} ...", flush=True)
        result = run_target(wt_path)
        results.append(result)

        status = "PWN " if result.pwn else "FAIL"
        if result.error:
            status = "ERR "
        elapsed = f"{result.wall_time_seconds:.1f}s"
        print(f"  [{status}] {platform}/{slug}  {elapsed}", flush=True)

    report = aggregate(results, walkthroughs)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "report": asdict(report),
        "results": [asdict(r) for r in results],
        "platforms_scanned": sorted({plat for _, plat in pairs}),
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print()
    print(f"  Total: {report.total_targets}  Pwned: {report.pwned}  "
          f"Rate: {report.pwn_rate * 100:.1f}%  Errors: {report.errors}")
    print(f"  Report -> {out_path}")

    return 0 if report.errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
