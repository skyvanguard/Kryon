"""F16.1 — stratified sample of NYU CTF Bench challenges.

Pinned once to `f16_sample.json` so subsequent iterations bench the same set.
F13 lesson: corpus pinned before any measurement.
"""
from __future__ import annotations

import json
import os
import random
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH_ROOT = HERE / "NYU_CTF_Bench" / "development"
OUT = HERE / "f16_sample.json"

SEED = 42
N_PER_CATEGORY = 5   # 5 × 6 = 30 total
CATEGORIES = ["crypto", "forensics", "misc", "pwn", "rev", "web"]


def main() -> None:
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for chfile in sorted(BENCH_ROOT.rglob("challenge.json")):
        try:
            data = json.loads(chfile.read_text(encoding="utf-8"))
        except Exception:
            continue
        data["_path"] = str(chfile.parent.relative_to(BENCH_ROOT)).replace(os.sep, "/")
        data["_challenge_dir"] = str(chfile.parent)
        cat = data.get("category", "unknown")
        if data.get("flag") and cat in CATEGORIES:
            by_cat[cat].append(data)

    rng = random.Random(SEED)
    sample: list[dict] = []
    for cat in CATEGORIES:
        pool = by_cat[cat]
        if len(pool) <= N_PER_CATEGORY:
            sample.extend(pool)
        else:
            sample.extend(rng.sample(pool, N_PER_CATEGORY))

    # Keep slim — drop absolute paths, keep relative for portability.
    slim = [
        {
            "name": c["name"],
            "category": c["category"],
            "description": c.get("description", ""),
            "files": c.get("files", []),
            "has_box": bool(c.get("box")),
            "box": c.get("box", ""),
            "points": c.get("points", 0),
            "flag": c["flag"],  # ground truth
            "path": c["_path"],
        }
        for c in sample
    ]
    OUT.write_text(json.dumps({"seed": SEED, "n": len(slim), "challenges": slim}, indent=2), encoding="utf-8")
    print(f"Wrote {len(slim)} challenges to {OUT}")
    from collections import Counter
    c = Counter(x["category"] for x in slim)
    for cat, n in sorted(c.items()):
        print(f"  {cat}: {n}")


if __name__ == "__main__":
    main()
