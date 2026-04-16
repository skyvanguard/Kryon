"""F16.5 — full non-box sample (29 challenges) for tight CI.

Non-box means no docker container needed. The agent works with local files
only: analysis, crypto, forensics, rev — challenges where the flag is
derivable from provided files + computation.

Excluded: pwn-with-box, web-with-server — those need remote target infra.
Can add in F16.6 when docker-bench target is set up.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH_ROOT = HERE / "NYU_CTF_Bench" / "development"
OUT = HERE / "f16_sample_nonbox.json"


def main() -> None:
    challenges: list[dict] = []
    for chfile in sorted(BENCH_ROOT.rglob("challenge.json")):
        try:
            c = json.loads(chfile.read_text(encoding="utf-8"))
        except Exception:
            continue
        if c.get("box") or not c.get("flag"):
            continue
        c["_path"] = str(chfile.parent.relative_to(BENCH_ROOT)).replace(os.sep, "/")
        challenges.append({
            "name": c["name"],
            "category": c["category"],
            "description": c.get("description", ""),
            "files": c.get("files") or [],
            "has_box": False,
            "box": "",
            "points": c.get("points", 0),
            "flag": c["flag"],
            "path": c["_path"],
        })

    # Deterministic order: sort by path
    challenges.sort(key=lambda x: x["path"])
    OUT.write_text(json.dumps({"n": len(challenges), "challenges": challenges}, indent=2), encoding="utf-8")
    from collections import Counter
    c = Counter(x["category"] for x in challenges)
    print(f"{len(challenges)} non-box challenges → {OUT}")
    for cat, n in sorted(c.items()):
        print(f"  {cat}: {n}")


if __name__ == "__main__":
    main()
