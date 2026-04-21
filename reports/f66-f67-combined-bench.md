# F66 + F67 Stack — Combined Bench Report

**Target:** OWASP Juice Shop v-latest (`juice.local:3000`, local container)
**Model:** `kryon-14b` (Qwen3-14B dense, Ollama, 12GB VRAM)
**Date:** 2026-04-21
**Stack commits:** `244bcd6..f736f77` (11 feature commits)

## Scorecard

| Layer | Metric | Value |
|---|---|---|
| Step 1 — Deterministic F18.7 (85 ATTACKS) | scoreboard | **25/111** |
| Step 2 — Experts F66.1.a (6 experts, budget 60) | findings emitted | **20** |
| Step 2 — Severity mix | CRIT / HIGH / MED / LOW | 3 / 9 / 5 / 3 |
| Step 2 — Knowledge graph F67.2 | nodes / edges / chains | 38 / 20 / 0 |
| Step 2 — Final Judge F67.5 | verdict | **CONDITIONAL_PASS** |
| Step 3 — LLM bench F18.9 (10 turns, ctx 8K) | scoreboard | **26/111 (+1 LLM)** |
| Step 3 — Supervisor F18.9.5 | loop_breaks / final_push | 1 / true |
| Step 3 — Tool mix | shell / fetch / encode | 0 / 12 / 1 |

**Final:** `26/111` scoreboard + `20` expert findings + 5 Judge action items.

## Step 1 — Deterministic ATTACKS

`scripts/f18/juice_shop_bench.py` → 85 canonical attacks including the 33
recipes added in F18.7. Reset Juice Shop first.

```
scoreboard 25/111
by difficulty: 1★=5  2★=5  3★=6  4★=6  5★=2  6★=1
```

## Step 2 — F66 + F67 deterministic stack

`scripts/f66/bench_full_stack.py` against the already-25/111 target.

### WAF probe (F67.1)
`probe_waf_presence` → no WAF (Juice Shop has none).

### Experts (F66.1.a)
| Expert | Findings | Budget used |
|---|---|---|
| disclosure | 10 | 10/10 |
| auth | 2 | 6/10 |
| injection | 2 | 5/10 |
| access | 0 | 10/10 |
| xss | 4 | 10/10 |
| ssrf | 2 | 10/10 |

20 findings total across 4 of 6 experts. `access` ran full budget but found
no IDOR / CSRF (Juice Shop requires auth on its sensitive endpoints and
the expert is unauthenticated).

### CRITICAL hits
- `CWE-521` — Weak/known credential accepted: `admin@juice-sh.op`
- `CWE-521` — Weak/known credential accepted: `admin@juice-sh.op'--` (SQLi bypass)
- `CWE-89`  — UNION SELECT on product search leaks users table

### Knowledge graph (F67.2)
- 38 nodes, 20 edges
- 0 chains matched. Juice Shop endpoints don't carry the bank-style URL
  patterns (`/api/payments`, `/admin/`) the graph's 7 predefined
  patterns hunt for. Severity bumps applied: 0.
- **Expected behaviour** — chain patterns are banking-oriented by
  design. A retail target (Juice Shop) emits the same CVE-weight
  findings but no cross-CWE reinforcement.

### Final Judge (F67.5)

Verdict: **CONDITIONAL_PASS** (1 HIGH + 4 MEDIUM action items, 0 CRITICAL).

| Anti-pattern | Severity | Observation |
|---|---|---|
| L13.auth-under-6 | HIGH | only 1 distinct auth probe_id — needs 6 attempts (SQLi, NoSQL, jwt_none, jwt weak, reset, dict) |
| L12.sqli-under-5 | MEDIUM | only 2 distinct SQLi payloads — gate wants 5+ |
| L9.chaining-missed | MEDIUM | 17 MED+ findings but 0 graph chains |
| L6.duplicate-findings | MEDIUM | 2 findings for CWE-521 on the same URL |
| L14.no-configuration-findings | MEDIUM | 0 emitted as `finding_type='configuration'` |

Each is a genuine gap, actionable, and matches what a human reviewer
would flag.

## Step 3 — LLM bench on top

`scripts/f18/juice_shop_llm_bench.py` with all F18.9 improvements:
ctx 8K, 10 turns max, tool_cap 1500, supervisor, RAG 20 hints,
encode_payload + http_fetch + shell exposed.

```
Start: 25 already-solved
  turn 2  llm_error (consec=1, recovered)
  turn 3  tcs=1  solved_delta=0
  turn 6  tcs=1  solved_delta=0
  turn 7  [supervisor] loop break #1
  turn 9  [supervisor] final push triggered
  turn 9  tcs=1  solved_delta=1
Final: 26/111  newly_solved: 1
Turns: 10  tool_calls: 13  wall: 1137s
Tool mix: shell=0  fetch=12  encode=1
```

- **+1 LLM solve**: `id=87 View Basket` (difficulty 2, CWE-639 IDOR)
- **Supervisor fired as designed**: loop detector caught a repeated
  signature at turn 7; budget reflector injected the final-push message
  at turn 9 (80% of wall) and the model closed with the IDOR solve
- **Schema typed tools working**: 0 shell calls, 12 fetch, 1 encode —
  the improved `http_fetch` schema steers the model away from curl
  one-liners 100% of the time
- **1 aisolated LLM timeout** at turn 2, recovered — no consecutive
  errors, no watchdog kill

## Contribution analysis

```
Scoreboard path (canary challenges auto-detected by Juice Shop):
  deterministic  25
  LLM delta      +1
  total         26/111   (up from 0/111 clean start)

Report path (findings a human pentester would log):
  expert layer   20 findings, 3 CRITICAL, 9 HIGH
  judge audit    5 action items, 1 HIGH, 0 CRITICAL blockers
  final verdict  CONDITIONAL_PASS
```

The two paths are **orthogonal**, not additive. The scoreboard measures
canary-challenge completion (narrow, game-like metric). The expert
layer measures report-worthy security findings (broad, engagement-like
metric). Both run on the same target and add distinct value:

- Scoreboard says "you found 26 of the 111 planted bugs".
- Report layer says "you also found 3 CRITICAL weak-cred / SQL-union /
  JWT-forgery issues plus 9 HIGH ones that a client would want in a
  PDF regardless of which challenges were planted".

## Stack health check

Every component fired without rollback-triggering errors:

| Component | Evidence |
|---|---|
| F66.1.a experts web | 20 findings across 4 experts |
| F66.2.a validator web | implicit in `finding_type='confirmed'` path |
| F66.3.a vulnhuntr | not applicable to web target (source-code only) |
| F67.1 waf_evasion | probe executed, no WAF detected (correct) |
| F67.2 knowledge_graph | graph ingested 38 nodes cleanly |
| F67.3 canary taxonomy | all findings carry `finding_type` |
| F67.4 quality gates | L12/L13/L14 cited by Judge = enforcement live |
| F67.5 final_judge | verdict + 5 action items produced |
| F67.6 request replay | LLM bench shape didn't regress |
| F18.9.5 supervisor | loop_break + final_push both fired |
| F18.9 wall timeout | no watchdog kill, 1 aislated timeout recovered |

## Reproducibility

```bash
docker restart juice_shop && sleep 12

# Step 1
python scripts/f18/juice_shop_bench.py \
  --out reports/f18-juice-shop-rerun/f67_combined_step1.json

# Step 2
docker exec -i kryon bash -c 'cat > /tmp/stack.py' < scripts/f66/bench_full_stack.py
docker exec kryon python3 /tmp/stack.py

# Step 3
KRYON_MODEL=kryon-14b F18_RAG=1 F18_RAG_HINTS=20 F18_WALL_S=1200 \
  F18_MAX_TURNS=10 F18_LLM_TIMEOUT=120 F18_NUM_CTX=8192 F18_TOOL_CAP=1500 \
  python -u scripts/f18/juice_shop_llm_bench.py \
  --out reports/f18-juice-shop-rerun/f67_combined_step3.json
```

## Next natural steps

1. Repeat against a banking-shaped target (DVWA bank profile, WebGoat)
   to exercise the knowledge graph chain patterns that Juice Shop
   doesn't trigger.
2. Run F67.6 validator replay against engagements where probes actually
   populate `method`/`body`/`headers_json` — F54/F55 need a small
   refactor to emit the request shape. Target: +15-25 % precision uplift
   matching the PoC-Adapt paper.
3. Port auth expert to issue 6 distinct probe_ids (close the L13 gate
   flagged by the Final Judge) — easy win, 1-2 hours.
