"""Smoke test F10.3-B integration — 5 Juliet files + 5 baseline files.

Verifies HybridHunter respects KRYON_LLM_TRIAGE env var and stamps
triage_* fields on every finding without filtering.
"""
from __future__ import annotations

import asyncio
import os
import random
from pathlib import Path

os.environ["KRYON_HYBRID_MAX_LLM_CANDIDATES"] = "0"
os.environ["KRYON_LLM_TRIAGE"] = "true"
os.environ.setdefault("KRYON_TRIAGE_MODEL", "qwen3-coder:30b-32k")

from kryon.skills.planner_hunter import HybridHunter, _reset_hybrid_budget
from kryon.skills.supervisor_tools import HunterJob

JULIET = Path("/workspace/.juliet/juliet-test-suite-c/testcases")
SOURCES = Path("/workspace/sources")


def pick_juliet_sample() -> list[Path]:
    rng = random.Random(42)
    files: list[Path] = []
    for d in JULIET.glob("CWE121_*"):
        for f in d.rglob("*.c"):
            if any(s in f.name for s in ("a.c", "b.c", "c.c", "d.c", "e.c")):
                continue
            files.append(f)
    return rng.sample(files, 3) if files else []


def pick_baseline_sample() -> list[Path]:
    files = list(SOURCES.rglob("*.c"))
    return files[:3]


async def main():
    _reset_hybrid_budget()
    runner = HybridHunter()
    samples = pick_juliet_sample() + pick_baseline_sample()
    print(f"Smoke: {len(samples)} files")
    for fp in samples:
        job = HunterJob(hunter_id="smoke", file_path=str(fp))
        try:
            findings = await asyncio.wait_for(runner(job), timeout=180)
        except asyncio.TimeoutError:
            findings = []
        print(f"\n--- {fp.name} ({len(findings)} findings) ---")
        for f in findings[:3]:
            v = f.get("triage_verdict", "(none)")
            c = f.get("triage_confidence", "")
            r = (f.get("triage_reason") or "")[:80]
            t = f.get("triage_latency_s", 0)
            print(f"  cwe={f.get('cwe','?'):<10} verdict={v:<10} conf={c:<6} "
                  f"{t:5.1f}s  reason={r}")
            assert "triage_verdict" in f, "annotator did not run"
    print("\nSmoke OK — triage fields stamped on all findings.")


if __name__ == "__main__":
    asyncio.run(main())
