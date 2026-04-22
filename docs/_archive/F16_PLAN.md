# F16 — CTF benchmark + Transilience-style iteration sprint

**Date**: 2026-04-16. **Reference**: Transilience CommunityTools (100% CTF with 23
markdown skills, no fine-tune, cross-model transferable). Kryon has 67 skills but
never measured on CTF benchmark, never iterated on fails.

## Hypothesis

Replicating Transilience methodology on Kryon's existing skill architecture with
a smaller local model (qwen3-coder-a3b) can reach meaningful CTF success rate.

## Gate (pinned pre-bench, will NOT move)

| Success rate | Verdict |
|--------------|---------|
| ≥50% | **SHIP** pentest product. Kryon demo-ready autonomous pentest. |
| 30-50% | **PARTIAL** — co-pilot mode viable, autonomous weak. Document, ship compliance + assistant. |
| <30% | **FAIL** — local-only ceiling reached. Pivot: Claude API hybrid (Camino A) or compliance-only (Camino C). |

Gate criterion: bootstrap 95% CI lower bound. NOT point estimate. F8 lesson.

## Phases

### F16.0 — Infrastructure (this session, ~1h)

- [ ] Pull `qwen3-coder:a3b` or equivalent MoE with small active params
- [ ] Set `KRYON_MODEL=qwen3-coder:a3b-instruct` default
- [ ] Sanity test: REPL boots, simple recon query responds in <60s
- [ ] Measure tokens/sec baseline vs qwen3-30b (target: 5-10× faster)

### F16.1 — Benchmark pinning (this session, ~1h)

- [ ] Evaluate candidates: NYU CTF Bench (200, academic), Cybench (40, pro),
      PicoCTF (educational), Transilience's 104 (reference bench)
- [ ] Pick primary: **NYU CTF Bench** (arXiv 2406.05590, 200 challenges across
      crypto/web/rev/pwn/forensics, reproducible, git repo)
- [ ] Pin corpus commit SHA (F13 lesson)
- [ ] Ground truth: flags + challenge metadata (category, difficulty) extracted

### F16.2 — Harness (this session, ~1h)

- [ ] `scripts/f16/ctf_bench.py` — iterates challenges, calls Kryon agent,
      grades by flag match
- [ ] Per-challenge budget: 15 min wall, 50 turns max, then mark fail
- [ ] Output: `docs/bench_results/f16_ctf_raw.jsonl` with per-challenge record
      {id, category, difficulty, success, turns, wall_s, last_tool, fail_reason}
- [ ] Seed fixed, challenge order shuffled once, committed

### F16.3 — Baseline run (overnight / ~8-10h)

- [ ] Sample 30 challenges stratified across 5 categories (6 each)
- [ ] Run Kryon agent on each; log everything
- [ ] Compute success rate + bootstrap 95% CI

### F16.4 — Iteration cycles (2-3 weeks, 3 cycles)

Per cycle:
- Fail classification (which category? which missing technique?)
- Skill patch (Transilience method: write missing technique into skill file)
- Re-bench SAME 30 challenges
- Track delta + CI non-overlap vs previous iteration

Stop after 3 cycles OR when CI lower bound crosses 50%.

### F16.5 — Gate evaluation + decision

Per pinned gate above. Writeup `F16_RESULTS.md`, BENCHMARKS.md entry.

## Anti-patterns (DO NOT do)

From F7→F13 experience:
- Don't shop corpora if numbers look bad. F13 bench stays, even if hard.
- Don't move gate from 50% to 40% "because close". Zone gris is zone gris.
- Don't iterate indefinitely. 3 cycles max.
- Don't add skills without a specific fail that required them. Transilience added
  skills for measured gaps, not speculative coverage.
- Don't swap models mid-bench. Model pin for the full benchmark cycle.

## Budget

- This session: F16.0 + F16.1 + F16.2 (~3h compute + writing)
- Overnight: F16.3 baseline (automated)
- Next 2-3 weeks (offline): F16.4 cycles
- Close: F16.5 writeup

## Success definition

Shippable outcome at sprint close, regardless of direction:

- ≥50% → Kryon pentest product has empirical backing. Ship, demo BCP.
- 30-50% → Documented "Kryon co-pilot" claim with measured performance.
- <30% → Pivot documented; F11.1-style clear evidence for next direction.

All three are productive outcomes. Only "negative sprint with nothing learned"
is failure.
