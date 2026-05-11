"""F10.3-B gate scoring — triage precision with bootstrap CI.

Ground truth rules:
  - Juliet file: a triage on a CWE-matching finding ground-truths to TP.
    Other-CWE triages on the same file are ambiguous (could be TP on a
    different CWE family) and are EXCLUDED from precision calc.
  - Baseline (clean real-world) file: all triages ground-truth to FP.

Precision metrics:
  - SUPPRESS precision = # SUPPRESS on FP-ground-truth / # SUPPRESS total.
  - KEEP precision     = # KEEP on TP-ground-truth / # KEEP total.

Gate (per F10.3-B plan):
  - SUPPRESS precision >= 65% (CI lower-bound)
  - KEEP precision     >= 50% (CI lower-bound)
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path


def bootstrap_ci(labels: list[int], n: int = 2000, seed: int = 42) -> tuple[float, float, float]:
    if not labels:
        return (0.0, 0.0, 0.0)
    rng = random.Random(seed)
    m = len(labels)
    point = sum(labels) / m
    samples = [sum(labels[rng.randrange(m)] for _ in range(m)) / m for _ in range(n)]
    samples.sort()
    return (point, samples[n // 40], samples[-n // 40])


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--bench", required=True, help="bench JSON with triage_verdicts")
    p.add_argument("--runner", default="hybrid-triage")
    a = p.parse_args()

    doc = json.loads(Path(a.bench).read_text())

    # Collect (verdict, confidence, gt) tuples.
    # Only pull from per_file_details if the bench saved them. Otherwise,
    # re-parse recall rows + fpr row structure.
    entries: list[dict] = []
    # recall section: each CWE row has per_runner[runner].per_file_details (if bench was extended)
    # For simplicity, assume bench aggregates triage_verdicts at top level.
    # We fall back to scanning any "triage_verdicts" present.

    # The bench writes per_runner aggregates, not per-file. To keep this
    # script generic, we also accept a sidecar "per_file" file.
    per_file_path = Path(a.bench).with_suffix(".per_file.json")
    if per_file_path.is_file():
        for r in json.loads(per_file_path.read_text()):
            if r.get("runner") != a.runner:
                continue
            gt_is_tp_target = r.get("cwe_target")  # int or 0
            for tv in r.get("triage_verdicts") or []:
                # Baseline: cwe_target == 0 -> FP.
                # Juliet: cwe_target > 0 -> FP unless cwe matches target.
                if gt_is_tp_target == 0:
                    gt = "FP"
                elif tv["is_cwe_match"]:
                    gt = "TP"
                else:
                    gt = "AMBIG"
                entries.append({
                    "verdict": tv["verdict"],
                    "confidence": tv["confidence"],
                    "gt": gt,
                })
    else:
        print(f"No per-file sidecar at {per_file_path}; "
              f"bench must be re-run with per-file output enabled.",
              file=sys.stderr)
        return 2

    supp = [e for e in entries if e["verdict"] == "SUPPRESS" and e["gt"] != "AMBIG"]
    keep = [e for e in entries if e["verdict"] == "KEEP" and e["gt"] != "AMBIG"]
    unc = [e for e in entries if e["verdict"] == "UNCERTAIN" and e["gt"] != "AMBIG"]
    err = [e for e in entries if e["verdict"] in ("ERROR", "")]

    supp_labels = [1 if e["gt"] == "FP" else 0 for e in supp]
    keep_labels = [1 if e["gt"] == "TP" else 0 for e in keep]

    p_supp, supp_lo, supp_hi = bootstrap_ci(supp_labels)
    p_keep, keep_lo, keep_hi = bootstrap_ci(keep_labels)

    print("\nEntries analysed (non-ambiguous):")
    print(f"  SUPPRESS n={len(supp):4d}   KEEP n={len(keep):4d}   UNCERTAIN n={len(unc):4d}   ERROR n={len(err):4d}")
    print()
    print(f"SUPPRESS precision = {p_supp*100:5.1f}%  95% CI [{supp_lo*100:.1f}, {supp_hi*100:.1f}]  "
          f"target ≥ 65% (CI lower bound)")
    print(f"KEEP     precision = {p_keep*100:5.1f}%  95% CI [{keep_lo*100:.1f}, {keep_hi*100:.1f}]  "
          f"target ≥ 50% (CI lower bound)")

    gate_supp = supp_lo >= 0.65
    gate_keep = keep_lo >= 0.50

    print()
    if gate_supp and gate_keep:
        print("GATE PASS — triage annotation ships as default.")
        return 0
    fails = []
    if not gate_supp:
        fails.append(f"SUPPRESS CI lower {supp_lo*100:.1f}% < 65%")
    if not gate_keep:
        fails.append(f"KEEP CI lower {keep_lo*100:.1f}% < 50%")
    print(f"GATE FAIL: {'; '.join(fails)}")
    print("Decision per F10.3-B plan: ship as experimental / opt-in only,")
    print("or drop if signal is below noise.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
