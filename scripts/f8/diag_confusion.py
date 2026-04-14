"""F8.0 — per-file CWE confusion diagnosis.

For each file in the F8 bench corpus (same seed as F6.3 R2):
  - run hybrid (heuristic + semgrep, the F6.3 R2 baseline)
  - if hunter flagged something but cwe_matched=False:
      emit (expected_cwe, emitted_cwes, rule_ids, hunters, snippet)

Output: docs/bench_results/f8_confusion.json
         + stdout table grouped by expected CWE

No fix code. No pattern expansion. Read-only introspection.
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

os.environ["KRYON_HYBRID_MAX_LLM_CANDIDATES"] = "0"
os.environ.setdefault("KRYON_JOERN_ENABLED", "false")

from kryon.skills.planner_hunter import HybridHunter, _reset_hybrid_budget
from kryon.skills.supervisor_tools import HunterJob

JULIET = Path(
    os.environ.get(
        "KRYON_JULIET_ROOT",
        "/workspace/.juliet/juliet-test-suite-c/testcases",
    )
)

_CWE_DIR_PATTERN = {
    121: "CWE121_*", 122: "CWE122_*", 190: "CWE190_*",
    416: "CWE416_*", 476: "CWE476_*", 415: "CWE415_*",
    134: "CWE134_*",
}


def find_cwe_files(cwe: int, n: int, seed: int = 42) -> list[Path]:
    """MUST match scripts/bench_juliet.py::find_cwe_files exactly."""
    pat = _CWE_DIR_PATTERN.get(cwe)
    if not pat:
        return []
    rng = random.Random(seed)
    candidates: list[Path] = []
    for d in JULIET.glob(pat):
        if not d.is_dir():
            continue
        for f in d.rglob("*.c"):
            name = f.name
            if any(suf in name for suf in ("a.c", "b.c", "c.c", "d.c", "e.c")):
                continue
            candidates.append(f)
    rng.shuffle(candidates)
    return candidates[:n]


async def scan_file(runner: HybridHunter, fp: Path) -> list[dict]:
    job = HunterJob(hunter_id="f8diag", file_path=str(fp))
    try:
        return await asyncio.wait_for(runner(job), timeout=120)
    except Exception:
        return []


def _cwe_matches(expected_label: str, emitted: list[str]) -> bool:
    try:
        from kryon.skills.patterns import cwes_match
        return any(cwes_match(e, expected_label) for e in emitted)
    except ImportError:
        return any(expected_label.lower() in e.lower() for e in emitted)


async def main():
    cwes = [121, 122, 190, 416, 476]
    n = 20
    _reset_hybrid_budget()
    runner = HybridHunter()

    per_file_records: list[dict] = []
    mismatch_samples: dict[int, list[dict]] = defaultdict(list)
    category_totals: Counter = Counter()

    for cwe in cwes:
        files = find_cwe_files(cwe, n)
        expected = f"CWE-{cwe}"
        print(f"\n[{expected}] {len(files)} files...")
        for fp in files:
            findings = await scan_file(runner, fp)
            emitted = [f.get("cwe", "") for f in findings if f.get("cwe")]
            matched = _cwe_matches(expected, emitted)
            rec = {
                "file": fp.name,
                "expected_cwe": expected,
                "n_findings": len(findings),
                "emitted_cwes": emitted,
                "matched": matched,
                "rules": sorted({
                    f.get("_semgrep_rule_id") or f.get("_joern_rule_id") or
                    f.get("_heuristic_pattern") or ""
                    for f in findings
                } - {""}),
                "hunters": sorted({f.get("_hunter", "") for f in findings}),
            }
            per_file_records.append(rec)

            # Focus on @any hit but NOT @CWE — those are the mislabels.
            if findings and not matched:
                if len(mismatch_samples[cwe]) < 10:
                    mismatch_samples[cwe].append(rec)

    # --- Categorise every mismatch. Heuristics for F8.0 only; validated
    # against real docstrings/metadata in F8.1.
    def categorise(rec: dict) -> str:
        exp = rec["expected_cwe"].replace("CWE-", "")
        emitted = rec["emitted_cwes"]
        if not emitted:
            return "no_cwe_emitted"
        # Emitted parent class of a well-known child — alias issue candidate.
        # F8 will validate these against cwes_match.
        parent_child = {
            "787": {"121", "122"},          # Out-of-bounds write parent
            "125": {"126", "127"},          # Out-of-bounds read parent
            "664": {"415", "416", "476"},   # Improper resource control
            "20":  {"134", "78"},           # Input validation parent
        }
        for parent, children in parent_child.items():
            if exp in children and f"CWE-{parent}" in emitted:
                return "alias_parent_child"
        # Different unrelated CWE → likely attribution bug in hunter
        # (pattern fired on wrong CWE category).
        return "attribution_or_metadata"

    for rec in per_file_records:
        if rec["n_findings"] > 0 and not rec["matched"]:
            category_totals[categorise(rec)] += 1

    # --- Write output
    out = {
        "corpus": {"cwes": cwes, "samples_per_cwe": n, "seed": 42},
        "per_file": per_file_records,
        "mismatch_samples": dict(mismatch_samples),
        "category_totals": dict(category_totals),
    }
    out_path = Path("/workspace/f8_confusion.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2))
    print(f"\nwritten: {out_path}")

    # --- Markdown summary to stdout
    print("\n" + "=" * 72)
    print("F8.0 CONFUSION MATRIX")
    print("=" * 72)
    for cwe in cwes:
        files = [r for r in per_file_records if r["expected_cwe"] == f"CWE-{cwe}"]
        mismatched = [r for r in files if r["n_findings"] > 0 and not r["matched"]]
        print(f"\nCWE-{cwe}: {len(mismatched)}/{len(files)} mismatches (flagged but wrong label)")
        for rec in mismatched[:5]:
            print(f"  {rec['file'][:60]:<60} emitted={rec['emitted_cwes']}  hunters={rec['hunters']}")

    print("\n" + "=" * 72)
    print("CATEGORY TOTALS (F8.1 sub-fase routing)")
    print("=" * 72)
    for cat, cnt in category_totals.most_common():
        print(f"  {cat:<30} {cnt}")


if __name__ == "__main__":
    asyncio.run(main())
