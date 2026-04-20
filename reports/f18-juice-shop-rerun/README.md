# F18 — Juice Shop Re-Bench Results (2026-04-20)

Re-run of the OWASP Juice Shop benchmark against the current Kryon
stack. Two LLM configurations tested plus deterministic baseline.

## Headline

| Run | Model | Solved | % | Wall |
|---|---|---:|---:|---:|
| Deterministic (canonical attack × 25) | — | **11 / 111** | 9.9 % | ~14 s |
| LLM session #1 | kryon-14b (Qwen3-14B, dense) | **+1** → 12/111 | 10.8 % | ~18 min *(hung, killed — pre-fix)* |
| LLM session #2 | qwen3-coder:30b-32k (A3B Coder) | **+0** → 11/111 | 9.9 % | 598 s *(wall fix working)* |

**Key finding:** the larger **30B coder-specialised** model did **not**
beat the smaller **14B general-purpose** model on this benchmark. The
30B Coder is tuned for code completion, not web-exploit reasoning, and
VRAM spillover (18 GB model on 12 GB GPU → 92 % utilisation, offload
to RAM) slowed inference to ~20 s per turn without adding quality.

## Run details

### Deterministic (11 solves)

Canonical attack battery — same as F18 baseline.

| id | challenge | category | diff |
|---:|---|---|---:|
| 4 | registerAdminChallenge | Improper Input Validation | 3★ |
| 19 | directoryListingChallenge | Sensitive Data Exposure | 1★ |
| 22 | deprecatedInterfaceChallenge | Security Misconfiguration | 2★ |
| 23 | easterEggLevelOneChallenge | Broken Access Control | 4★ |
| 27 | errorHandlingChallenge | Security Misconfiguration | 1★ |
| 35 | forgottenDevBackupChallenge | Sensitive Data Exposure | 4★ |
| 53 | misplacedSignatureFile | Observability Failures | 4★ |
| 67 | passwordRepeatChallenge | Improper Input Validation | 1★ |
| 70 | resetPasswordJim | Broken Authentication | 3★ |
| 85 | unionSqlInjectionChallenge | Injection | 4★ |
| 97 | exposedMetricsChallenge | Observability Failures | 1★ |

Difficulty mix: 1★×3, 2★×1, 3★×2, 4★×5. Median 4★.

### LLM #1 — kryon-14b (Qwen3-14B dense, 9.3 GB, fits VRAM)

- 40 turns / 15 min wall configured
- **+1 solve**: `nullByteChallenge` (id 105, Improper Input Validation, 4★)
- Session hung after 18 min (urllib timeout didn't expire — bug #1 below)
- Manually killed to record score

### LLM #2 — qwen3-coder:30b-32k (Q4, 18 GB, VRAM spillover)

- 30 turns / 20 min wall configured
- 29 tool calls executed, 1 timeout
- Final wall: 598 s (terminated cleanly under budget — wall fix works)
- **+0 solves** despite 29 curl/attack attempts
- VRAM at 92 % (11.3 / 12.2 GB) — each inference paged through RAM
- Average per-turn latency: ~20 s

## Bug fixes applied

1. **Wall-clock budget was not respected** (caused hang in session #1):
   - Fix: clamp `call_llm(timeout_s=...)` to the remaining wall budget
     on every turn so a hung Ollama request cannot exceed the wall.
   - Fix: add threading.Timer-based watchdog that calls `os._exit(124)`
     at `WALL_S + 20%` grace as a hard safety net.
   - Fix: new env var `F18_LLM_TIMEOUT` (default 120 s) for per-call
     timeout, separate from the outer wall (`F18_WALL_S`).
   - Validated: 60 s wall smoke test terminated at 66 s (4 s slack).
   - Validated: session #2 wall=1200 s terminated at 598 s cleanly.

2. **Ollama request sometimes times out mid-turn** but the bench
   correctly catches it, increments `consecutive_errors`, trims the
   oldest message pair, and continues. After 3 consecutive errors
   the session aborts (pre-existing behavior, now observable).

## Why the 30B lost to the 14B

Two independent factors:

- **Task mismatch.** OWASP Juice Shop rewards web-semantic reasoning
  (HTTP payload manipulation, SQLi variants, JWT manipulation).
  qwen3-coder:30b is tuned on programming corpora and tends to write
  *larger* scripts but fewer *exploit* variations.
- **VRAM budget.** 18 GB Q4 model on 12 GB GPU forces partial CPU
  offload, pushing per-turn latency from ~3 s (dense 14B) to ~20 s
  (30B coder). Fewer effective rounds of attack in the same wall.

**Implication for banking engagements:** prefer `kryon-14b` as the
primary pentest model. Reserve the 30B coder for source-code-audit
workflows (F5+ hunter agents) where its code-reading strength pays off.

## Historical comparison

| Run | Model | Stack | Solved |
|---|---|---|---:|
| F18 | — (deterministic only) | base | 11/111 |
| F18.1 | kryon-30b-moe | base | 0/111 (VRAM) |
| F19 | Foundation-Sec-8B-Reasoning | base | 0/111 (timeout) |
| F20 | Qwen3-14B (kryon-14b) | base | 9/111 |
| **today #1** | **Qwen3-14B (kryon-14b)** | **F53-F64** | **12/111 (+3 vs F20)** |
| **today #2** | **qwen3-coder:30b-32k** | **F53-F64** | 11/111 *(0 LLM solves)* |

Net score on current stack: **12 / 111 = 10.8 %** with Qwen3-14B.

## Files

| File | Description |
|---|---|
| `bench_result.json` | Session #1 — Qwen3-14B snapshot |
| `qwen3_coder_30b.json` | Session #2 — qwen3-coder:30b raw output |
| `README.md` | This writeup |

Deterministic raw JSON is in `docs/bench_results/f18_juice_shop.json`.
