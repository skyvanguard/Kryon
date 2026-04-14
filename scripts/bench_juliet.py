"""
F5.3 — Juliet Test Suite benchmark for Kryon hunters.

Measures recall@CWE and proxy FPR across our 4 runners (heuristic,
semgrep, hybrid, llm) using NIST's Juliet C/C++ 1.3 (105K test cases).

Methodology
-----------
Each Juliet file is a single self-contained test case with bad+good
sections gated by #ifndef OMITBAD / #ifndef OMITGOOD. For our static
scanners (semgrep, heuristic) we don't compile — we just scan source.

Two metrics per (CWE, runner):

  RECALL@CWE = fraction of bad-containing files where the runner
               emitted at least one finding (CWE match preferred,
               but any finding counts as detection signal).

  FPR_PROXY  = fraction of HARDENED real-world files (e.g., zlib
               source) where the runner emitted findings. zlib is
               our 'known clean' control set; high FPR there means
               the runner is noisy.

Why this differs slightly from canonical Juliet runs:
  - We don't compile (no -DOMITGOOD/-DOMITBAD split). Bad+good in
    one file is more conservative for recall (we should still flag
    the bad pattern present) and slightly less precise for FPR.
  - LLM runner is not benchmarked at scale (20-30 min per file
    times 100+ files = days). Use --runners semgrep,heuristic,hybrid
    by default. LLM mode tested separately on small samples.

Usage
-----
  python bench_juliet.py
    --cwes 121,122,134,190,416,476
    --samples-per-cwe 30
    --runners semgrep,heuristic,hybrid
    --baseline-repo /workspace/sources/...zlib...
    --baseline-files 30

Output
------
  Markdown table to stdout + JSON dump to /workspace/hunts/bench_juliet.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
import time
from pathlib import Path

JULIET_ROOT = Path(os.environ.get(
    "KRYON_JULIET_ROOT",
    "/workspace/.juliet/juliet-test-suite-c/testcases",
))

# CWE -> testcase directory glob
_CWE_DIR_PATTERN = {
    121: "CWE121_*",
    122: "CWE122_*",
    124: "CWE124_*",
    125: "CWE126_*",   # Buffer Overread maps to CWE-125 in our taxonomy
    127: "CWE127_*",
    134: "CWE134_*",
    190: "CWE190_*",
    191: "CWE191_*",
    415: "CWE415_*",
    416: "CWE416_*",
    476: "CWE476_*",
    787: "CWE121_*",   # No CWE787 in Juliet; 121+122 cover OOB write
}


def find_cwe_files(cwe: int, n: int, seed: int = 42) -> list[Path]:
    """Sample N test-case files for the given CWE, excluding helpers."""
    pat = _CWE_DIR_PATTERN.get(cwe)
    if not pat:
        return []
    rng = random.Random(seed)
    candidates: list[Path] = []
    for d in JULIET_ROOT.glob(pat):
        if not d.is_dir():
            continue
        for f in d.rglob("*.c"):
            # Skip multi-file helper variants (a/b/c/d split files) for simplicity
            name = f.name
            if any(suffix in name for suffix in ("a.c", "b.c", "c.c", "d.c", "e.c")):
                continue
            candidates.append(f)
    rng.shuffle(candidates)
    return candidates[:n]


# ---------------------------------------------------------------------------
# Per-file scan (single hunter on a single file, no full hunt machinery)
# ---------------------------------------------------------------------------


async def scan_one(runner_type: str, file_path: Path, cwe: int) -> dict:
    """Run a single hunter against one file. Returns shape:
       {file, runner, n_findings, cwe_matched, finding_cwes[], duration_s}
    """
    from kryon.skills.planner_hunter import (
        HeuristicHunter, SemgrepHunter, HybridHunter, _reset_hybrid_budget,
    )
    from kryon.skills.supervisor_tools import HunterJob

    job = HunterJob(hunter_id="bench", file_path=str(file_path))
    if runner_type == "heuristic":
        runner = HeuristicHunter()
    elif runner_type == "semgrep":
        runner = SemgrepHunter()
    elif runner_type == "hybrid":
        # Force LLM-off for benchmark (would take days). Hybrid degrades
        # to semgrep-with-budget-zero, still useful for measuring the
        # combined-stage decision (verified vs pattern-only).
        os.environ["KRYON_HYBRID_MAX_LLM_CANDIDATES"] = "0"
        _reset_hybrid_budget()
        runner = HybridHunter()
    else:
        raise ValueError(f"unknown runner: {runner_type}")

    t0 = time.time()
    findings: list[dict] = []
    try:
        findings = await asyncio.wait_for(runner(job), timeout=120)
    except asyncio.TimeoutError:
        pass
    except Exception:
        pass
    elapsed = time.time() - t0

    finding_cwes = [f.get("cwe", "") for f in findings if f.get("cwe")]
    cwe_label = f"CWE-{cwe}"
    # F6.4 — use alias-aware matching so emitting a parent CWE
    # (e.g. CWE-787) counts as a match for child CWE labels (CWE-121, 122).
    try:
        from kryon.skills.patterns import cwes_match
        cwe_matched = any(cwes_match(c, cwe_label) for c in finding_cwes)
    except ImportError:
        cwe_matched = any(cwe_label.lower() in c.lower() for c in finding_cwes)
    return {
        "file": file_path.name,
        "runner": runner_type,
        "cwe_target": cwe,
        "n_findings": len(findings),
        "cwe_matched": cwe_matched,
        "finding_cwes": finding_cwes[:5],
        "duration_s": round(elapsed, 2),
    }


# ---------------------------------------------------------------------------
# Benchmark driver
# ---------------------------------------------------------------------------


async def run_recall_for_cwe(
    cwe: int, n_samples: int, runners: list[str]
) -> dict:
    """For one CWE, scan N samples with each runner, compute recall."""
    files = find_cwe_files(cwe, n_samples)
    if not files:
        return {"cwe": cwe, "n_files": 0, "per_runner": {}}

    print(f"\n[CWE-{cwe}] sampled {len(files)} files...")
    per_runner: dict[str, dict] = {}

    for runner in runners:
        any_finding = 0
        cwe_matched = 0
        total_findings = 0
        total_dur = 0.0
        for fp in files:
            r = await scan_one(runner, fp, cwe)
            if r["n_findings"] > 0:
                any_finding += 1
            if r["cwe_matched"]:
                cwe_matched += 1
            total_findings += r["n_findings"]
            total_dur += r["duration_s"]
        per_runner[runner] = {
            "n_files": len(files),
            "any_finding": any_finding,
            "cwe_matched": cwe_matched,
            "recall_any": round(any_finding / len(files), 3),
            "recall_cwe_match": round(cwe_matched / len(files), 3),
            "avg_findings_per_file": round(total_findings / len(files), 2),
            "avg_duration_s": round(total_dur / len(files), 2),
        }
        print(
            f"  {runner:<10} recall@any={per_runner[runner]['recall_any']:.0%}  "
            f"recall@CWE={per_runner[runner]['recall_cwe_match']:.0%}  "
            f"avg={per_runner[runner]['avg_findings_per_file']:.1f} findings/file  "
            f"{per_runner[runner]['avg_duration_s']:.1f}s/file"
        )

    return {"cwe": cwe, "n_files": len(files), "per_runner": per_runner}


async def run_fpr_proxy(
    repo_files: list[Path], runners: list[str]
) -> dict:
    """Scan known-clean source files, count findings as FPR proxy."""
    print(f"\n[FPR proxy] scanning {len(repo_files)} clean baseline files...")
    per_runner: dict[str, dict] = {}
    for runner in runners:
        files_with_finding = 0
        total_findings = 0
        for fp in repo_files:
            r = await scan_one(runner, fp, cwe=0)
            if r["n_findings"] > 0:
                files_with_finding += 1
            total_findings += r["n_findings"]
        per_runner[runner] = {
            "n_files": len(repo_files),
            "files_with_finding": files_with_finding,
            "fpr_proxy": round(files_with_finding / max(1, len(repo_files)), 3),
            "total_findings": total_findings,
        }
        print(
            f"  {runner:<10} fpr_proxy={per_runner[runner]['fpr_proxy']:.0%}  "
            f"({files_with_finding}/{len(repo_files)} files)  "
            f"{total_findings} total findings"
        )
    return per_runner


def render_markdown_table(results: dict) -> str:
    cwes = [r for r in results["recall"] if r["per_runner"]]
    runners = list(cwes[0]["per_runner"].keys()) if cwes else []
    lines: list[str] = []
    lines.append("## Juliet Recall (CWE-match)")
    lines.append("")
    lines.append("| CWE | files | " + " | ".join(runners) + " |")
    lines.append("|---|---|" + "|".join("---" for _ in runners) + "|")
    for r in cwes:
        row = [f"CWE-{r['cwe']}", str(r["n_files"])]
        for runner in runners:
            v = r["per_runner"][runner]["recall_cwe_match"]
            row.append(f"{v:.0%}")
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    lines.append("## Recall@any-finding (less strict, useful as triage signal)")
    lines.append("")
    lines.append("| CWE | files | " + " | ".join(runners) + " |")
    lines.append("|---|---|" + "|".join("---" for _ in runners) + "|")
    for r in cwes:
        row = [f"CWE-{r['cwe']}", str(r["n_files"])]
        for runner in runners:
            v = r["per_runner"][runner]["recall_any"]
            row.append(f"{v:.0%}")
        lines.append("| " + " | ".join(row) + " |")
    if results.get("fpr"):
        lines.append("")
        lines.append("## FPR proxy (clean baseline)")
        lines.append("")
        lines.append("| runner | files_with_finding | total_findings | fpr_proxy |")
        lines.append("|---|---|---|---|")
        for runner, v in results["fpr"].items():
            lines.append(
                f"| {runner} | {v['files_with_finding']}/{v['n_files']} | "
                f"{v['total_findings']} | {v['fpr_proxy']:.0%} |"
            )
    return "\n".join(lines)


async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cwes", default="121,122,190,416,476",
                   help="comma-separated CWE numbers to bench")
    p.add_argument("--samples-per-cwe", type=int, default=20,
                   help="files per CWE to sample")
    p.add_argument("--runners", default="heuristic,semgrep,hybrid",
                   help="comma-separated runners")
    p.add_argument("--baseline-repo", default="/workspace/sources",
                   help="dir to glob for clean baseline files")
    p.add_argument("--baseline-files", type=int, default=15,
                   help="how many baseline files to scan for FPR")
    p.add_argument("--out", default="/workspace/hunts/bench_juliet.json")
    args = p.parse_args()

    cwes = [int(c.strip()) for c in args.cwes.split(",") if c.strip()]
    runners = [r.strip() for r in args.runners.split(",") if r.strip()]

    print("=" * 72)
    print(f"F5.3 Juliet benchmark")
    print(f"  CWEs:    {cwes}")
    print(f"  Samples: {args.samples_per_cwe} per CWE")
    print(f"  Runners: {runners}")
    print("=" * 72)

    t_start = time.time()
    recall_results = []
    for cwe in cwes:
        recall_results.append(await run_recall_for_cwe(cwe, args.samples_per_cwe, runners))

    # FPR proxy: scan a few real-world files from baseline_repo
    baseline_files: list[Path] = []
    for ext in ("*.c",):
        baseline_files.extend(Path(args.baseline_repo).rglob(ext))
    baseline_files = baseline_files[: args.baseline_files]
    fpr_results = {}
    if baseline_files:
        fpr_results = await run_fpr_proxy(baseline_files, runners)
    else:
        print(f"\n[FPR proxy] no baseline files found in {args.baseline_repo}")

    elapsed = time.time() - t_start

    out = {
        "cwes": cwes,
        "samples_per_cwe": args.samples_per_cwe,
        "runners": runners,
        "duration_s": round(elapsed, 1),
        "recall": recall_results,
        "fpr": fpr_results,
        "baseline_repo": args.baseline_repo,
        "baseline_files_scanned": len(baseline_files),
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2))

    print()
    print("=" * 72)
    print(f"Total wall time: {elapsed:.1f}s")
    print("=" * 72)
    print()
    print(render_markdown_table(out))
    print()
    print(f"Full results: {args.out}")


if __name__ == "__main__":
    asyncio.run(main())
