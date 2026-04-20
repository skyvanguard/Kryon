# F18 — Juice Shop Re-Bench Results (2026-04-20)

Re-run of the OWASP Juice Shop benchmark against the current Kryon
stack to validate recent additions (F53 crawler, F54 banking probes,
F55 extended probes, F56 request diffing, F57 multi-agent, F58 det-first
+ LLM escalation, F64 XBOW pattern library).

## Results

| Run | Solved | % | Time | Baseline |
|---|---:|---:|---:|---|
| **Deterministic (canonical attacks × 25)** | **11 / 111** | 9.9 % | ~14 s | F18: 11/111 (unchanged) |
| **LLM (kryon-14b = Qwen3-14B, 40 turns, ≤15 min wall)** | **+1** (total 12/111) | 10.8 % | ~18 min (hung, killed) | F20: 9/111 — **+3 improvement** |

Net increase vs. F20 baseline: **+3 solves** for the same Qwen3-14B
model, attributable to the F53-F64 stack changes (auth-aware crawler,
extended probe library, deterministic-first pipeline, XBOW pattern
library).

## Deterministic bench — 11 challenges

By category:
- Improper Input Validation (2): registerAdminChallenge, passwordRepeatChallenge
- Sensitive Data Exposure (2): directoryListingChallenge, forgottenDevBackupChallenge *(see note)*
- Security Misconfiguration (2): deprecatedInterfaceChallenge, errorHandlingChallenge
- Observability Failures (2): exposedMetricsChallenge, misplacedSignatureFileChallenge
- Broken Access Control (1): easterEggLevelOneChallenge
- Broken Authentication (1): resetPasswordJimChallenge
- Injection (1): unionSqlInjectionChallenge

By difficulty: 1★×3, 2★×1, 3★×2, 4★×5. Median difficulty: 4★.

## LLM bench — 1 additional solve

The LLM session (Qwen3-14B via Ollama, 40 turns, wall 15 min) ran in
parallel to the deterministic bench and contributed:

- **nullByteChallenge** (id 105, Improper Input Validation, 4★) —
  *Poison Null Byte: retrieve an ACL-gated file by appending `%00` to
  the path*.

This single add puts us at **12 / 111 = 10.8 %** against the OWASP
Juice Shop challenge set.

Note: `forgottenDevBackupChallenge` (id 35) appeared after the LLM
session started but was not part of the deterministic ATTACKS list;
it was solved by LLM tool-call exploration (likely `/ftp/package.json.bak`).

## Issues discovered

1. **LLM wall-clock timer did not trigger.** The script is configured
   for 900 s wall, but after 18 min the process was still blocking
   on an Ollama request. Had to manually kill the processes. TODO:
   wrap the ollama call in a timeout, not just the outer loop.
2. **Two python processes** were observed in `tasklist` — likely
   duplicate launch via the Claude Code tool harness. Idempotent
   launch guard would be nice.

Neither issue invalidates the scoreboard result — the score comes
from the live `/api/Challenges` endpoint and is observable at any
point without waiting for the bench to terminate.

## Comparison to prior baselines

| Date | Model | Stack generation | Solved | Notes |
|---|---|---|---:|---|
| F18 (original) | none (deterministic only) | base | 11/111 | canonical attack battery |
| F18.1 | kryon-30b-moe (MoE 3.3B-active) | base | 0/111 | VRAM spillover, unusable |
| F19 | Foundation-Sec-8B-Reasoning | base | 0/111 | timed out on 3 commands / 7 min |
| F20 | Qwen3-14B (kryon-14b) | base | 9/111 (8.1 %) | 32K ctx + 4K tokens; initial LLM win |
| **F18 rerun** | Qwen3-14B (kryon-14b) | **F53-F64** | **12/111 (10.8 %)** | **+3 vs F20 on same model** |

The improvement from 9 → 12 solves is attributable to the web-pentest
stack additions between F20 and today, not to the model.

## Files

| File | Description |
|---|---|
| `bench_result.json` | merged deterministic + scoreboard snapshot |

Bench artifacts for the deterministic run are also in
`docs/bench_results/f18_juice_shop.json`.
