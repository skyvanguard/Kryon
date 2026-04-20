# F18.3 — RAG-assisted Juice Shop Benchmark

Added a semantic retriever over a 39-writeup corpus and injected the
top-20 known-working payloads into the LLM system prompt at session
start.

## Headline

| Configuration | Solved | Δ vs baseline |
|---|---:|---:|
| Deterministic (52 attacks) | 14 / 111 | — |
| + Qwen3-14B, no RAG | 12 / 111 | −2 (flaky, hung mid-run) |
| **+ Qwen3-14B, RAG on** | **15 / 111** | **+1 over deterministic** |

The +1 LLM solve was **Login Jim** (id 49, 3★ Injection): the RAG hint
for `loginJimChallenge` landed in the top-20 that was spliced into the
system prompt, and the model executed it verbatim in turn 5.

## Components

### 1. Writeup corpus — `docs/juice_shop_writeups.json`

39 curated Juice Shop challenge writeups. Each entry has:

```json
{
  "key": "loginAdminChallenge",
  "name": "Login Admin",
  "category": "Injection",
  "difficulty": 2,
  "payload": "curl -s -X POST ... ' OR 1=1--",
  "solution": "SQL injection on /rest/user/login..."
}
```

Content is open knowledge from the Pwning Juice Shop guide (CC-BY-SA).

### 2. Retriever — `scripts/f18/juice_shop_rag.py`

- Embeds each writeup's `name + category + solution` blob via
  Ollama `nomic-embed-text`
- Cosine similarity for query retrieval
- Jaccard-on-tokens fallback when Ollama is unreachable (so the bench
  never hard-fails on the embedding backend)
- Mode auto-detected at build time, reported via `describe()`

### 3. Bench integration — `scripts/f18/juice_shop_llm_bench.py`

New env vars:

| Var | Default | Purpose |
|---|---:|---|
| `F18_RAG` | `0` | `1` to enable RAG hints in the system prompt |
| `F18_RAG_HINTS` | `15` | Number of writeups to splice in |

When enabled, the prompt gains a `PROVEN PAYLOADS FROM KNOWLEDGE BASE`
block listing the top-N writeup names + one-line payloads (≤260 chars
each to stay within the 32K context).

## Observations

- **Per-turn latency stayed flat**: ~2 min per LLM call on Qwen3-14B
  (32K context with a longer system prompt). 40-turn budget burned
  only 7 turns with 5-way batched tool calls = 22 executions.
- **The wall fix held**: terminated at 926 s on a 900 s budget (hit
  the cap cleanly, no hang).
- **RAG precision is good**: top-1 for "login as admin SQL injection"
  returns `loginAdminChallenge` at 0.768 cosine — correct.
- **RAG coverage is narrow**: many 4★+ challenges in the corpus
  describe multi-step chains (JWT RS→HS forging, XXE, price-
  manipulation) that need more than a single curl to trigger.
  Single-shot LLM sessions rarely chain these correctly.

## Why only +1?

Looking at what RAG hints the LLM actually tried:

1. `loginAdminChallenge` — already solved by deterministic
   (`sql_login_bypass` in ATTACKS list) → duplicate.
2. `loginJimChallenge` — **solved** (genuine new win). ✅
3. `loginBenderChallenge` — LLM tried but challenge already
   server-flagged from admin login cascade.
4. `xxeFileDisclosureChallenge` — model couldn't build the multi-step
   `echo ... > /tmp/xxe.xml && curl -F file=@...` chain correctly in
   its tool-call format.
5. `forgedJwtChallenge` (6★) — needs Python + RSA key extraction; the
   model wrote the intent but not the executable code.

Most RAG hits **overlap** the deterministic battery. The next +N
solves require either:
- Chains that span turns (use tool results from turn N in turn N+1)
- Browser-side XSS triggers (headless Chrome)
- Multi-request timing (e.g. CAPTCHA abuse via 10 rapid POSTs)

## Historical progression

| Bench | Date | Stack | Model | Solved | Notes |
|---|---|---|---|---:|---|
| F18 | original | base | — | 11 / 111 | 25-attack battery |
| F20 | earlier | base | Qwen3-14B | 9 / 111 | first LLM win |
| F18-rerun | 2026-04-20 | F53-F64 | Qwen3-14B | 12 / 111 | +3 from stack changes |
| F18-rerun | 2026-04-20 | F53-F64 | qwen3-coder:30b | 11 / 111 | larger model, 0 LLM solves |
| **F18.2** | 2026-04-20 | +25 attacks | — | **14 / 111** | deterministic expansion |
| **F18.3** | 2026-04-20 | +RAG | Qwen3-14B | **15 / 111** | **current record** |

## Next amplifiers (in order of expected ROI)

1. **Multi-turn tool chaining** — wire `shell` tool results back into
   the next turn's planning phase. Expected +3-5 solves.
2. **Headless Playwright for DOM XSS** — `F51` already ships the
   wrapper; integrate into the bench for ~15 XSS challenges.
3. **CAPTCHA burst** — a dedicated attack routine that fires 10
   feedbacks in <10 s. Expected +2 solves (Captcha Bypass, Zero Stars).
4. **Deterministic expansion to 80-100 attacks** — diminishing
   returns but cheap.
5. **Larger RAG corpus (100+ writeups)** — only helps after 1-3 ship.

## Files

| File | Description |
|---|---|
| `docs/juice_shop_writeups.json` | 39-entry RAG corpus |
| `scripts/f18/juice_shop_rag.py` | Retriever (embed + cosine / jaccard fallback) |
| `scripts/f18/juice_shop_llm_bench.py` | Bench with `F18_RAG=1` support |
| `reports/f18-juice-shop-rerun/qwen3_14b_rag.json` | Raw run output |
| `reports/f18-juice-shop-rerun/RAG_RESULTS.md` | This writeup |
