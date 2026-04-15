"""F10.3-B gate check — precision of triage verdicts on spike dataset."""
from __future__ import annotations

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


def main(path: str) -> None:
    data = json.loads(Path(path).read_text())

    supp = [r for r in data if r["verdict"] == "SUPPRESS"]
    keep = [r for r in data if r["verdict"] == "KEEP"]
    unc = [r for r in data if r["verdict"] == "UNCERTAIN"]

    supp_labels = [1 if r["ground_truth"] == "FP" else 0 for r in supp]
    keep_labels = [1 if r["ground_truth"] == "TP" else 0 for r in keep]

    p_supp, supp_lo, supp_hi = bootstrap_ci(supp_labels)
    p_keep, keep_lo, keep_hi = bootstrap_ci(keep_labels)

    print(f"SUPPRESS  n={len(supp):3d}  precision={p_supp*100:5.1f}%  "
          f"95% CI [{supp_lo*100:.1f}, {supp_hi*100:.1f}]  target ≥ 65%")
    print(f"KEEP      n={len(keep):3d}  precision={p_keep*100:5.1f}%  "
          f"95% CI [{keep_lo*100:.1f}, {keep_hi*100:.1f}]  target ≥ 50%")
    print(f"UNCERTAIN n={len(unc):3d}  "
          f"(gt=FP {sum(1 for r in unc if r['ground_truth']=='FP')}, "
          f"gt=TP {sum(1 for r in unc if r['ground_truth']=='TP')})")

    gate_supp = p_supp >= 0.65
    gate_keep = p_keep >= 0.50
    if gate_supp and gate_keep:
        print("\nGATE POINT ESTIMATES PASS. CI tightness depends on N.")
    else:
        fails = []
        if not gate_supp: fails.append(f"SUPPRESS {p_supp*100:.1f}% < 65%")
        if not gate_keep: fails.append(f"KEEP {p_keep*100:.1f}% < 50%")
        print(f"\nGATE FAILS on point estimate: {'; '.join(fails)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/workspace/f10_spike_qwen.json")
