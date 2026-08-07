"""Cybench bench CLI — run Kryon (capable profile) over a set of Cybench tasks.

Usage (clone Cybench separately — Apache-2.0, NOT bundled):
    git clone https://github.com/andyzorigin/cybench   # on the server
    # smoke test the adapter with no container/model:
    KRYON_BENCH_DRY_RUN=1 python -m scripts.cybench --tasks-root <cybench>/benchmark --limit 1
    # real run against V4 (capable) in the kryon container:
    python -m scripts.cybench --tasks-root <cybench>/benchmark --category crypto --out reports/cybench.json

Baseline to beat (Cybench paper, unguided %solved): best model ~17.5%; frontier now ~93-100%.
The value is the DELTA: V4-bare vs V4+Kryon-harness on the same tasks.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scripts.cybench.loader import load_task
from scripts.cybench.runner import run_task
from scripts.cybench.scorer import aggregate


def discover_tasks(tasks_root: Path, *, category: str = "", limit: int = 0) -> list[Path]:
    """Find every metadata/metadata.json under a Cybench benchmark tree."""
    metas = sorted(tasks_root.rglob("metadata/metadata.json"))
    if category:
        metas = [m for m in metas if f"/{category}/" in m.as_posix()]
    if limit:
        metas = metas[:limit]
    return metas


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Cybench benchmark harness for Kryon (capable profile)")
    ap.add_argument("--tasks-root", required=True, help="path to the cloned Cybench 'benchmark' dir")
    ap.add_argument("--category", default="", help="restrict to a category (crypto/web/pwn/rev/forensics/misc)")
    ap.add_argument("--limit", type=int, default=0, help="cap the number of tasks (0 = all)")
    ap.add_argument("--easy", action="store_true", help="use easy_prompt (with hints) instead of hard (standard)")
    ap.add_argument("--timeout", type=int, default=900, help="per-task timeout seconds")
    ap.add_argument("--model", default=None, help="override KRYON_BENCH_MODEL for this run")
    ap.add_argument("--out", default="reports/cybench.json", help="path to write the aggregated JSON report")
    args = ap.parse_args(argv)

    root = Path(args.tasks_root)
    if not root.exists():
        print(f"tasks-root not found: {root}", file=sys.stderr)
        return 2

    metas = discover_tasks(root, category=args.category, limit=args.limit)
    if not metas:
        print(f"no Cybench tasks found under {root} (category={args.category or 'all'})", file=sys.stderr)
        return 1
    print(f"running {len(metas)} task(s) [{args.category or 'all categories'}] in capable profile ...")

    scores = []
    for i, meta in enumerate(metas, 1):
        task = load_task(meta)
        print(f"  [{i}/{len(metas)}] {task.name} ({','.join(task.categories)}) ...", flush=True)
        res = run_task(task, hard=not args.easy, timeout=args.timeout, model=args.model)
        scores.append(res.score)
        mark = "PWN" if res.score.solved else f"{res.score.subtasks_hit}/{res.score.subtasks_total}"
        print(f"        -> {mark}")

    report = aggregate(scores)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(
        f"\nunguided: {report['solved']}/{report['tasks']} solved "
        f"({report['unguided_pct']}%) · subtask macro {report['subtask_macro_pct']}% · report -> {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
