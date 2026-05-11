"""
F3.9 benchmark — extended hunt against libxml2 (and zlib baseline).

Measures what the F3 plan promised:
  1. Wall-clock speedup from bounded parallelism
     (parallel=1 vs 2 vs 4 on the same budget)
  2. VRAM peak during a hunt (sampled via nvidia-smi on the host)
  3. Validator TP/FP distribution at scale
  4. Dedup effectiveness (raw_findings vs unique verdicts)

Uses the HEURISTIC runner — no LLM required. This measures the
ARCHITECTURE (pool + validator + coordinator), not gemma4's reasoning.
Real-LLM benchmarks belong in F4 once the corpus lands.

Run from the kryon container:
    docker exec kryon python /opt/bench_f3_libxml2.py

Targets tried in order; each can be run standalone or all together.
"""
from __future__ import annotations

import asyncio
import json
import os
import statistics
import subprocess

# --- VRAM sampling ---
# We run a side thread that polls nvidia-smi; if not available we skip.
import threading
import time
from pathlib import Path


class VramSampler:
    """Background sampler for GPU memory.used (MiB)."""

    def __init__(self, interval_s: float = 0.5):
        self.interval_s = interval_s
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.samples: list[int] = []

    def _have_nvidia_smi(self) -> bool:
        try:
            subprocess.run(
                ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=2, check=False,
            )
            return True
        except Exception:
            return False

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                r = subprocess.run(
                    ["nvidia-smi", "--query-gpu=memory.used",
                     "--format=csv,noheader,nounits"],
                    capture_output=True, text=True, timeout=2, check=False,
                )
                if r.returncode == 0:
                    for line in r.stdout.strip().splitlines():
                        try:
                            self.samples.append(int(line.strip()))
                            break  # first GPU only
                        except ValueError:
                            pass
            except Exception:
                pass
            self._stop.wait(self.interval_s)

    def start(self) -> None:
        if not self._have_nvidia_smi():
            print("  (nvidia-smi not available — skipping VRAM sampling)")
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> dict:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if not self.samples:
            return {"peak_mib": None, "avg_mib": None, "samples": 0}
        return {
            "peak_mib": max(self.samples),
            "avg_mib": round(statistics.mean(self.samples), 1),
            "samples": len(self.samples),
        }


# --- Bench runner ---


async def run_one(repo_url: str, parallel: int, budget: int, ref: str = "") -> dict:
    from kryon.skills.planner_hunter import hunt_zero_days

    vram = VramSampler()
    vram.start()
    t0 = time.time()
    try:
        report = await hunt_zero_days(
            repo_url,
            budget=budget,
            parallelism=parallel,
            runner_type="heuristic",
            ref=ref,
        )
        error = ""
    except Exception as e:
        report = None
        error = str(e)[:200]
    elapsed = time.time() - t0
    vram_stats = vram.stop()

    return {
        "repo": repo_url,
        "parallel": parallel,
        "budget": budget,
        "ref": ref or "(HEAD)",
        "duration_s": round(elapsed, 2),
        "error": error,
        "vram": vram_stats,
        "report": (json.loads(report.to_json()) if report else None),
    }


def summarize(result: dict) -> str:
    r = result
    rep = r["report"]
    if rep is None:
        return f"  {r['repo'][:40]}  par={r['parallel']}  ERROR: {r['error']}"
    return (
        f"  par={r['parallel']}  "
        f"budget={r['budget']:>3}  "
        f"time={r['duration_s']:>6.2f}s  "
        f"files_scored={rep['files_scored']:>4}  "
        f"hunters={rep['hunters_spawned']:>3}  "
        f"raw={rep['raw_findings']:>3}  "
        f"conf={rep['confirmed_findings']:>3}  "
        f"rej={rep['rejected_findings']:>3}  "
        f"vram_peak={r['vram'].get('peak_mib') or '?'} MiB"
    )


async def main():
    print("=" * 74)
    print("F3.9 benchmark — architecture stress test at scale")
    print("=" * 74)

    # Matrix: (repo, budget, [parallel levels])
    # zlib is the canary (we already know it works). libxml2 is the real
    # target — larger repo, more realistic file count.
    targets: list[tuple[str, int, list[int]]] = [
        ("https://github.com/madler/zlib.git", 10, [1, 2, 4]),
        # libxml2 is ~400K LoC — big enough to exercise budgeting + parallelism
        ("https://github.com/GNOME/libxml2.git", 10, [1, 2, 4]),
    ]

    all_results: list[dict] = []

    for repo, budget, par_levels in targets:
        print()
        print(f"### Target: {repo}")
        print(f"    budget={budget}, parallel sweep={par_levels}")
        for par in par_levels:
            print(f"\n  -> running parallel={par}...")
            r = await run_one(repo, par, budget)
            all_results.append(r)
            print(summarize(r))

    # --- Speedup table ---
    print()
    print("=" * 74)
    print("Speedup vs serial (same repo + budget):")
    print("=" * 74)
    by_repo: dict[str, list[dict]] = {}
    for r in all_results:
        by_repo.setdefault(r["repo"], []).append(r)

    for repo, runs in by_repo.items():
        runs_sorted = sorted(runs, key=lambda x: x["parallel"])
        serial = next((r for r in runs_sorted if r["parallel"] == 1), None)
        if serial is None or not serial["report"]:
            continue
        print(f"\n{repo[:55]}")
        print(f"  baseline (parallel=1): {serial['duration_s']}s")
        for r in runs_sorted:
            if r["parallel"] == 1:
                continue
            speedup = serial["duration_s"] / r["duration_s"] if r["duration_s"] else 0
            print(f"    parallel={r['parallel']}: {r['duration_s']}s  "
                  f"speedup x{speedup:.2f}  "
                  f"vram_peak={r['vram'].get('peak_mib') or '?'} MiB")

    # --- Validator stats ---
    total_raw = sum(r["report"]["raw_findings"] for r in all_results if r["report"])
    total_conf = sum(r["report"]["confirmed_findings"] for r in all_results if r["report"])
    total_rej = sum(r["report"]["rejected_findings"] for r in all_results if r["report"])
    if total_raw:
        print()
        print(f"Validator aggregate: {total_raw} raw → "
              f"{total_conf} confirmed, {total_rej} rejected "
              f"(kill rate: {total_rej/total_raw*100:.1f}%)")

    # --- VRAM peak overall ---
    vram_peaks = [r["vram"].get("peak_mib") for r in all_results if r["vram"].get("peak_mib")]
    if vram_peaks:
        print(f"VRAM peak across all runs: {max(vram_peaks)} MiB "
              f"(cap target: 11264 MiB on 12 GB laptop)")

    # Save raw results for later analysis
    out = Path(os.environ.get("KRYON_HUNTS_DIR", "/workspace/hunts")) / "bench_f3.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(all_results, indent=2, default=str))
    print(f"\nFull results: {out}")


if __name__ == "__main__":
    asyncio.run(main())
