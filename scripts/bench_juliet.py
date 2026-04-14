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
       {file, runner, n_findings, cwe_matched, finding_cwes[],
        sources_seen[], hunters_failed[], duration_s}

    F7.5 — `hybrid-F7` = hybrid with JoernHunter enabled.
    `hybrid` (unchanged) = F6.3 R2 baseline (heuristic + semgrep).
    `joern-solo` = only JoernHunter — measures marginal contribution.
    """
    from kryon.skills.planner_hunter import (
        HeuristicHunter, SemgrepHunter, HybridHunter, _reset_hybrid_budget,
    )
    from kryon.skills.supervisor_tools import HunterJob

    job = HunterJob(hunter_id="bench", file_path=str(file_path))
    if runner_type == "heuristic":
        os.environ["KRYON_JOERN_ENABLED"] = "false"
        runner = HeuristicHunter()
    elif runner_type == "semgrep":
        os.environ["KRYON_JOERN_ENABLED"] = "false"
        runner = SemgrepHunter()
    elif runner_type == "hybrid":
        # F6.3 R2 baseline — Joern explicitly OFF.
        os.environ["KRYON_JOERN_ENABLED"] = "false"
        os.environ["KRYON_HYBRID_MAX_LLM_CANDIDATES"] = "0"
        _reset_hybrid_budget()
        runner = HybridHunter()
    elif runner_type == "hybrid-F7":
        # F7 candidate — Joern ON. CPGs expected in KRYON_JOERN_CPG_DIR;
        # missing CPGs trigger on-the-fly importCode with timeout.
        os.environ["KRYON_JOERN_ENABLED"] = "true"
        os.environ["KRYON_HYBRID_MAX_LLM_CANDIDATES"] = "0"
        _reset_hybrid_budget()
        runner = HybridHunter()
    elif runner_type == "joern-solo":
        os.environ["KRYON_JOERN_ENABLED"] = "true"
        from kryon.skills.planner_hunter import JoernHunter
        runner = JoernHunter()
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

    # F8.1.b — include rule-declared kryon_alias CWEs. Fixes the
    # plumbing bug where rule authors tagged a finding with multiple
    # legitimate CWEs (e.g. malloc-arith is CWE-190 primary but also
    # counts as CWE-122 / CWE-787) but only the primary reached the
    # match check. Env toggle lets F8.2 bootstrap compare pre vs post
    # without reverting code.
    ignore_aliases = os.environ.get("KRYON_BENCH_IGNORE_ALIASES", "").strip().lower() in {
        "1", "true", "yes", "on",
    }
    finding_cwes: list[str] = []
    for f in findings:
        primary = f.get("cwe", "")
        if primary:
            finding_cwes.append(primary)
        if not ignore_aliases:
            for alias in f.get("cwe_aliases") or []:
                if alias and alias not in finding_cwes:
                    finding_cwes.append(alias)
    cwe_label = f"CWE-{cwe}" if cwe else ""
    try:
        from kryon.skills.patterns import cwes_match
        cwe_matched = bool(cwe_label) and any(
            cwes_match(c, cwe_label) for c in finding_cwes
        )
    except ImportError:
        cwe_matched = bool(cwe_label) and any(
            cwe_label.lower() in c.lower() for c in finding_cwes
        )

    # Per-finding provenance (union of _sources or _hunter) for overlap
    # matrix. hybrid-F7 emits _sources; solo hunters emit _hunter.
    sources_seen: set[str] = set()
    hunters_failed: list[str] = []
    for f in findings:
        srcs = f.get("_sources") or []
        if srcs:
            sources_seen.update(srcs)
        elif f.get("_hunter"):
            sources_seen.add(f["_hunter"])
        for hf in f.get("_hunters_failed") or []:
            if isinstance(hf, dict) and hf.get("name"):
                hunters_failed.append(hf["name"])
            elif isinstance(hf, str):
                hunters_failed.append(hf)

    # Also look at the HunterJob status for joern when hybrid didn't produce
    # findings (silent-failure guard).
    if runner_type in ("hybrid-F7", "joern-solo"):
        j_status = getattr(job, "_joern_last_status", "")
        if j_status and j_status != "ok":
            hunters_failed.append("joern")

    return {
        "file": file_path.name,
        "runner": runner_type,
        "cwe_target": cwe,
        "n_findings": len(findings),
        "cwe_matched": cwe_matched,
        "finding_cwes": finding_cwes[:5],
        "sources_seen": sorted(sources_seen),
        "hunters_failed": sorted(set(hunters_failed)),
        "duration_s": round(elapsed, 2),
    }


# ---------------------------------------------------------------------------
# Benchmark driver
# ---------------------------------------------------------------------------


async def run_recall_for_cwe(
    cwe: int, n_samples: int, runners: list[str]
) -> dict:
    """For one CWE, scan N samples with each runner, compute recall +
    overlap-matrix + hunters_failed rate (F7.5)."""
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
        # F7.5 overlap matrix — for each file, what {heuristic|semgrep|joern}
        # source set produced a CWE-matching finding?
        overlap_counter: dict[tuple, int] = {}
        hunters_failed_files = 0
        per_file: list[dict] = []
        for fp in files:
            r = await scan_one(runner, fp, cwe)
            per_file.append(r)
            if r["n_findings"] > 0:
                any_finding += 1
            if r["cwe_matched"]:
                cwe_matched += 1
                # Bucket source combination for the overlap matrix.
                combo = tuple(r["sources_seen"] or ["<none>"])
                overlap_counter[combo] = overlap_counter.get(combo, 0) + 1
            total_findings += r["n_findings"]
            total_dur += r["duration_s"]
            if r["hunters_failed"]:
                hunters_failed_files += 1
        per_runner[runner] = {
            "n_files": len(files),
            "any_finding": any_finding,
            "cwe_matched": cwe_matched,
            "recall_any": round(any_finding / len(files), 3),
            "recall_cwe_match": round(cwe_matched / len(files), 3),
            "avg_findings_per_file": round(total_findings / len(files), 2),
            "avg_duration_s": round(total_dur / len(files), 2),
            "overlap": {
                "|".join(sorted(k)): v for k, v in overlap_counter.items()
            },
            "hunters_failed_files": hunters_failed_files,
            "hunters_failed_rate": round(hunters_failed_files / len(files), 3),
            # F8.2 — per-file {1,0} labels for bootstrap CI post-processing.
            # One int per file: cwe_matched (0/1). Needed so the CI estimator
            # doesn't need to re-run the bench.
            "per_file_cwe_matched": [1 if x["cwe_matched"] else 0
                                     for x in per_file],
            "per_file_any_finding": [1 if x["n_findings"] > 0 else 0
                                     for x in per_file],
        }
        print(
            f"  {runner:<12} recall@any={per_runner[runner]['recall_any']:.0%}  "
            f"recall@CWE={per_runner[runner]['recall_cwe_match']:.0%}  "
            f"avg={per_runner[runner]['avg_findings_per_file']:.1f} f/file  "
            f"failed={per_runner[runner]['hunters_failed_rate']:.0%}  "
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

    # F7.5 — overlap matrix + hunters_failed rate for runners that aggregate
    # multiple underlying hunters.
    lines.append("")
    lines.append("## F7.5 — Source overlap (where did the CWE-match come from?)")
    lines.append("")
    lines.append("| CWE | runner | source-combo | count |")
    lines.append("|---|---|---|---|")
    for r in cwes:
        for runner in runners:
            ov = r["per_runner"][runner].get("overlap") or {}
            if not ov:
                continue
            for combo, cnt in sorted(ov.items(), key=lambda x: -x[1]):
                lines.append(
                    f"| CWE-{r['cwe']} | {runner} | `{combo}` | {cnt} |"
                )

    lines.append("")
    lines.append("## F7.5 — hunters_failed rate")
    lines.append("")
    lines.append("| CWE | runner | files with any failed hunter | rate |")
    lines.append("|---|---|---|---|")
    for r in cwes:
        for runner in runners:
            rate = r["per_runner"][runner].get("hunters_failed_rate", 0)
            cnt = r["per_runner"][runner].get("hunters_failed_files", 0)
            if cnt == 0:
                continue
            lines.append(
                f"| CWE-{r['cwe']} | {runner} | {cnt}/{r['n_files']} | {rate:.0%} |"
            )

    return "\n".join(lines)


def _evaluate_gate(results: dict) -> dict:
    """F7.5 ship/rollback decision — hardcoded against the pre-agreed gate.

    Ship: recall@CWE +15pp on CWE-121 AND CWE-190 AND hybrid-F7 FPR <= 40%.
    Rollback: hybrid-F7 FPR > 45% OR any non-F7 CWE recall regresses.
    Grey zone: everything else — F7.6 tuning before shipping.
    """
    baseline_runner = "hybrid"
    candidate_runner = "hybrid-F7"
    verdict = {
        "gate": "undetermined",
        "notes": [],
        "recall_delta": {},
        "fpr_candidate": None,
    }
    recalls_by_cwe = {r["cwe"]: r["per_runner"] for r in results.get("recall", [])}
    f7_cwes = {121, 190}

    # Compute per-CWE recall@CWE deltas vs baseline.
    for cwe, per_runner in recalls_by_cwe.items():
        b = per_runner.get(baseline_runner, {}).get("recall_cwe_match")
        c = per_runner.get(candidate_runner, {}).get("recall_cwe_match")
        if b is None or c is None:
            continue
        delta_pp = round((c - b) * 100, 1)
        verdict["recall_delta"][cwe] = {
            "baseline": b, "candidate": c, "delta_pp": delta_pp,
        }

    # FPR from hybrid-F7 on clean baseline.
    fpr = results.get("fpr", {}).get(candidate_runner, {}).get("fpr_proxy")
    verdict["fpr_candidate"] = fpr
    fpr_base = results.get("fpr", {}).get(baseline_runner, {}).get("fpr_proxy")
    verdict["fpr_baseline"] = fpr_base

    # Rollback checks.
    if fpr is not None and fpr > 0.45:
        verdict["gate"] = "rollback"
        verdict["notes"].append(f"hybrid-F7 FPR {fpr:.0%} > 45% — rollback")
        return verdict
    for cwe, row in verdict["recall_delta"].items():
        if cwe not in f7_cwes and row["delta_pp"] < -2.0:
            verdict["gate"] = "rollback"
            verdict["notes"].append(
                f"CWE-{cwe} recall regressed {row['delta_pp']:+.1f}pp on "
                f"non-F7 target — rollback"
            )

    # Ship checks on F7 target CWEs.
    f7_deltas = [
        verdict["recall_delta"].get(cwe, {}).get("delta_pp", 0)
        for cwe in f7_cwes
    ]
    fpr_ok = fpr is not None and fpr <= 0.40
    f7_ok = all(d >= 15.0 for d in f7_deltas if d is not None)

    if verdict["gate"] == "undetermined":
        if f7_ok and fpr_ok:
            verdict["gate"] = "ship"
            verdict["notes"].append(
                "CWE-121 + CWE-190 both +≥15pp, FPR ≤ 40% — ship"
            )
        else:
            verdict["gate"] = "grey-zone"
            if not f7_ok:
                verdict["notes"].append(
                    f"F7-target deltas {f7_deltas} < 15pp threshold"
                )
            if not fpr_ok and fpr is not None:
                verdict["notes"].append(
                    f"FPR {fpr:.0%} above ship threshold (40%)"
                )
    return verdict


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
    # F7.5 — evaluate gate before writing output so the JSON carries it.
    if "hybrid-F7" in runners and "hybrid" in runners:
        out["gate"] = _evaluate_gate(out)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2))

    print()
    print("=" * 72)
    print(f"Total wall time: {elapsed:.1f}s")
    print("=" * 72)
    print()
    print(render_markdown_table(out))
    print()
    if out.get("gate"):
        g = out["gate"]
        print("=" * 72)
        print(f"F7.5 GATE VERDICT: {g['gate'].upper()}")
        for note in g["notes"]:
            print(f"  - {note}")
        print("=" * 72)
    print(f"Full results: {args.out}")


if __name__ == "__main__":
    asyncio.run(main())
