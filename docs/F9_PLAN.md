# F9 — FPR reduction sprint

> Written before any fix. Targets and stop criteria here are the contract:
> after the fact, only the bench output decides ship/rollback.

## Baseline (frozen 2026-04-14, post-F8.1.b)

Hybrid runner on 100 mixed real-world `.c` files from `/workspace/sources`:

| Metric | Point | 95% CI | Source |
|---|---|---|---|
| FPR proxy | **47.0%** | [37.0, 57.0] | `docs/bench_results/bench_f6_recalibration.json` |
| Recall@CWE pooled (7 CWEs, N=100/CWE) | **65.0%** | [61.4, 68.3] | same |
| FP root-cause distribution | A 34% / B 23% / C 25% / D 7% / E 10% | n/a | `docs/bench_results/f9_fps.json` |

Frozen snapshot: [`docs/bench_results/f9_baseline_frozen.json`](bench_results/f9_baseline_frozen.json).
**Every sub-phase compares against this snapshot, NOT a fresh re-run of the
baseline.** Re-running the baseline would inject between-run sampling noise
into the deltas.

## Sub-phase order — by execution risk, low to high

| Phase | Category | Why first/later | FP target | FPR target (CI non-overlap with 47%) |
|---|---|---|---|---|
| **F9.1** | C — sentinel NULL / fopen-var | Filter infra (`_passes_fpr_filters`) already exists, just extend it. 25% volume. Lowest implementation risk. | -34 | **≤ 38%** |
| **F9.2** | B — sizeof / safe-arith | Tighten Kryon rules (`pattern-not`) + heuristic literal-arith filter. 23% volume. Touches our rule YAMLs. | -32 | **≤ 28%** |
| **F9.3** | A — upstream too broad | Trailofbits rule overrides. Highest recall risk because the same patterns ARE bugs in some code. **Do NOT delete rules** — degrade severity or move to opt-in `--strict` profile. 34% volume. | -47 | **≤ 20%** (ship-real) |

Categories D (7%) and E (10%) are rolled into per-phase work where they
overlap; not standalone phases.

## Gates (defined before measuring)

### Per sub-phase (all must hold to ship that phase)

1. **FPR delta**: post-fix FPR upper-bound CI < pre-fix FPR lower-bound CI
   (CIs non-overlapping). Point-estimate-only deltas → reject.
2. **Recall preservation**: hybrid recall@CWE pooled does not drop more
   than 2pp without FPR dropping more than 5pp.
3. **Per-category recall sanity**: sample 10 of the FPs the fix eliminates.
   If >1 was a real TP mis-labelled in Juliet (e.g. the rule was correctly
   flagging a real bug class even on noise corpus), **rollback the fix**.
   Aggregated metrics can hide signal-erasure.
4. **Sub-phase target met**: phase FPR ≤ phase target above. Missing the
   target = sprint stops; remaining phases are signs of cola larga.

### Sprint-level

- **Ship full sprint**: F9.3 reaches ≤ 20% FPR with recall@CWE within 3pp
  of baseline 65.0%.
- **Ship partial**: F9.1 and/or F9.2 individually meet their gate. Ship
  what ships, document what didn't, stop.
- **Stop without shipping**: F9.1 alone misses gate → diagnostic re-run,
  this scoping was wrong.

## Methodology floor

- N=100 baseline files, same set across phases (cached if needed for
  deterministic comparison).
- Bootstrap 95% CI (`scripts/f9/bootstrap_ci.py`) on every reported delta.
- Numbers without CI are unvalidated and don't count.
- Per-category recall sanity is mandatory — written in scripts, not just
  in this doc.

## On Category A specifically (note for F9.3)

Trailofbits rules `insecure-use-memset` etc. are CORRECT for code that
genuinely fails to handle the pattern they detect. The Juliet baseline
files have low rates of those patterns; production code may not. Two
mitigation paths, both preserve the rule's value:

- **Severity demotion**: keep rule active, downgrade ERROR → INFO. The
  finding still surfaces but doesn't dominate output.
- **Profile gating**: move noisy rules to a `--strict` config flag. Default
  config is the Kryon-curated set; `--strict` re-adds the broad upstream
  rules for users who want maximum recall over precision.

**Do not delete a noisy upstream rule.** The right answer is making it
opt-in.
