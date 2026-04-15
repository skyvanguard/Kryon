# F13.2 — GnuCash precision (per category, bootstrap 95% CI)

Corpus: gnucash@9f8f4d9e. Seed: 42. Labeled 50 samples.

## Per-category precision

| Category | Pool | Sampled | TP | FP | UNK | Precision | 95% CI |
|----------|------|---------|----|----|-----|-----------|--------|
| CWE-476 | 143 | 30 | 3 | 27 | 0 | 10.00% | [0.00%, 20.00%] |
| CWE-121 | 17 | 17 | 5 | 10 | 2 | 33.33% | [13.33%, 60.00%] |
| CWE-190 | 3 | 3 | 0 | 0 | 3 | 0.00% | [0.00%, 0.00%] |

## Engine precision (CWE-121 + CWE-190, excl. CWE-476 known-noisy)

- Pooled N = 15
- Precision point = **33.33%**
- 95% CI = [13.33%, 60.00%]
- F13.2 engine gate threshold: **≥ 40%**
- Gate status: **FAIL** (CI lower bound comparison)

## Test-file contamination (parallel dimension)

- 4/50 sampled findings are in test/ dirs.
- Of those, 0 labeled TP (findings on real code paths exercised by tests).
- Priority-score leak documented; F14 fix: cap final score when _path_score returns 1.