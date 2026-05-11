# F85 — DeepSeek-R1-Distill-Qwen-14B vs `kryon-14b` A/B Bench Plan

## Hypothesis

The current `kryon-14b` (Qwen3-14B Instruct) carries Kryon's REPL well, but
the F18-F73 Juice Shop result of **85/111** comes mostly from deterministic
detectors (nuclei, sqlmap, hardcoded skill checks) rather than from the LLM
reasoning about novel exploit chains. Replacing the LLM with a reasoning
model (DeepSeek-R1-Distill-Qwen-14B) should:

- preserve every vuln currently caught by detectors (no regression),
- increase the count of vulns caught by **LLM reasoning alone**,
- and surface more chained exploits (e.g., IDOR → privilege escalation,
  SSRF → AWS metadata, login flow → JWT confusion).

If the reasoning model does not beat the instruct model on the
"LLM-only" bucket below, the bottleneck is not the model and we should
invest elsewhere (skill design, hybrid escalation, deterministic depth).

## Setup

```bash
# 1. Install the reasoning variant.
bash scripts/install_kryon_r1.sh

# 2. Confirm it shows up in Ollama.
docker exec kryon-ollama ollama list | grep kryon-r1-14b
```

## Bench surfaces

| Bench script | What it measures | Why it matters here |
|---|---|---|
| `scripts/f18/juice_shop_llm_bench.py` | LLM-only Juice Shop runs (no detector preflight). 111 vulns. | Direct reasoning signal — this is the bench that exposes whether the model can chain exploits. |
| `scripts/bench_juliet.py` | Juliet SAST (CWE coverage on synthetic C/C++/Java). | Tests reasoning over code without runtime tooling. |
| `scripts/f62/webpentest_bench.py` | Skill-augmented webpentest (LLM + deterministic detectors). | Confirms no regression in the production path. |

## Run matrix

```bash
# Baseline — current production model.
KRYON_MODEL=kryon-14b      uv run python scripts/f18/juice_shop_llm_bench.py
KRYON_MODEL=kryon-14b      uv run python scripts/bench_juliet.py
KRYON_MODEL=kryon-14b      uv run python scripts/f62/webpentest_bench.py

# Candidate — reasoning variant.
KRYON_MODEL=kryon-r1-14b   uv run python scripts/f18/juice_shop_llm_bench.py
KRYON_MODEL=kryon-r1-14b   uv run python scripts/bench_juliet.py
KRYON_MODEL=kryon-r1-14b   uv run python scripts/f62/webpentest_bench.py
```

Each run produces a JSON report under the bench's usual output directory.
Compare with `scripts/f18/_juliet_delta.py` style diff.

## Bucketing the results

The honest scorecard splits each Juice Shop hit into one of three buckets so
we can attribute the win/loss to the right system:

| Bucket | Definition | What a delta tells us |
|---|---|---|
| **A. Detector-only** | Caught by a deterministic skill (`pre_hooks`, nuclei, sqlmap, hardcoded probe) before the LLM had to decide. | Should be roughly equal across both models. A drop here means the model is interfering with a deterministic path — investigate. |
| **B. LLM-only** | Caught only because the LLM reasoned a chain or picked a non-obvious tool combination. | **This is the bucket that justifies the upgrade.** Reasoning models should win here or the swap is not worth it. |
| **C. Hybrid** | Detector flagged a candidate, LLM confirmed/exploited it. | Reasoning model should be neutral or better. Slower turns acceptable if accuracy improves. |

Implementation note: the existing bench logs `evidence_source` per hit
(detector name, tool call, or model assertion). Run with
`F18_LOG_EVIDENCE=true` and post-process with a tiny script (or extend
`_juliet_delta.py`) to bucket A/B/C.

## Known risks specific to reasoning models

1. **Thinking loops.** R1 distills can spend 1-3K tokens in `<think>` before
   emitting a tool call. On 16K ctx this eats history. Mitigations:
   - keep `num_predict 4096` (cap escape for runaway reasoning),
   - already-existing `KRYON_FORCE_TOOL_TURNS=8` forces tool use early,
   - if you see truncated tool calls, lower `num_ctx` to 12288 to leave room.

2. **Triage hangs.** `src/kryon/skills/triage_annotator.py:257` already
   warns reasoning-enabled models hang on trivial classification. Either:
   - keep `KRYON_TRIAGE_MODEL=kryon-14b` (cheap instruct) and only flip
     `KRYON_MODEL=kryon-r1-14b` for the main agent, **or**
   - accept the latency for end-to-end reasoning.

3. **`<think>` leaking into tool args.** The runtime in
   `sdk/agents/models/openai_chatcompletions.py` strips think blocks. If
   a tool call argument contains `<think>` text, file a regression — do
   not paper over it in the Modelfile.

4. **Per-turn latency.** Expect 2-4× slower turns on the same hardware.
   This is **acceptable by design**: Kryon is fully local-first, and the
   product decision is to pay turn latency in exchange for explicit
   reasoning. The A/B is not "is it fast enough" — it is "is the chain
   of thought finding things the instruct model misses".

## Architectural constraint — local-only inference

**No frontier API escalation.** Every reasoning step must run on the
operator's own hardware. This is a non-negotiable product constraint:

- Banking clients (BCP/SIB regulated) cannot have engagement context
  exfiltrated to OpenAI/Anthropic/Google during an audit.
- The reproducibility hashes (F39) only stay meaningful if the inference
  path is auditable end-to-end.
- Sales pitch is "self-hosted offensive AI", not "wrapper around Claude".

Consequence for this bench: there is no "fallback to API" branch. If
`kryon-r1-14b` underperforms `kryon-14b`, the next moves are all local:

1. **Bigger local reasoning model on bigger local hardware.** Move
   off 12 GB to 24-48 GB VRAM (RTX 4090 / A6000 / DGX Spark) and try
   `qwen2.5-32b-thinking`, `qwq-32b`, or `deepseek-r1-distill-llama-70b`.
2. **Better skill design.** Pre-compute more state in `pre_hooks` so
   the LLM has less to reason about per turn (already the F84 pattern).
3. **Deterministic depth.** Add more skills like `fortigate-audit` /
   `unifi-audit` where the LLM is just a narrator over wired checks.

## Decision rule (local-only)

After the bench, promote `kryon-r1-14b` to default (update
`docker-compose.kali.yml` `KRYON_MODEL` default) **if both are true**:

- Bucket B (LLM-only) on Juice Shop improves by ≥ 3 vulns absolute, OR
  Bucket C (hybrid) chain-exploit count improves measurably.
- Bucket A (detector-only) on Juice Shop drops by ≤ 1 vuln (no
  regression in the deterministic path).

Latency is not part of the decision rule — turn time is allowed to
grow as long as accuracy improves. Juliet recall is a safety check
(do not regress more than 5 pp) but not the primary signal: Juliet
rewards pattern matching, which is exactly what a reasoning model
should de-prioritise.

If neither bucket B nor C improves, the conclusion is that the
bottleneck is **not** model reasoning — it is skill design, tool
budget, or context layout. In that case, keep `kryon-14b` and
re-target to one of the three local moves above.

## After the bench — what to record

- Raw JSON outputs from each run, committed under
  `docs/benchmarks/results/F85/`.
- A short markdown summary with the three-bucket table filled in.
- Reproducibility hash from the existing F39 hashing pipeline so the
  result is auditable like the rest of the F18-F84 series.
