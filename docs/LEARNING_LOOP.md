# Kryon Self-Improving Loop v1

> Status: draft — v1 MVP
> Owner: skyvanguard
> Updated: 2026-04-12

## Problem

Kryon as shipped is a *stateless* agent framework: every engagement starts
from zero. The knowledge base is useful but static (MITRE, NVD, OWASP,
public writeups). Nothing that the agent **did** in a previous engagement
influences the next one. Handoffs between agents forget findings. There is
no feedback loop.

Goal of v1: **turn Kryon into a system that gets measurably better at
finding and exploiting vulnerabilities the more engagements it runs.**

## Non-goals for v1

- Fine-tuning the model
- RL / reward shaping
- Automatic prompt rewriting
- Sharing experiences across users or tenants
- Binary/exploit generation from mined chains

## Architecture (v1)

```
 user starts a new engagement
         │
         ▼
 ┌───────────────────────┐
 │ 1. Target Profiler    │  extract profile from user msg +
 │                       │  any early recon results
 └───────────┬───────────┘
             │ { host, ports, tech, os_hint, notes }
             ▼
 ┌───────────────────────┐
 │ 2. Experience Recall  │  query ChromaDB "kryon_experiences"
 │                       │  for top-K similar past engagements
 └───────────┬───────────┘
             │ top-K chains
             ▼
 ┌───────────────────────┐
 │ 3. Agent runs tools   │  every tool call is logged in the
 │                       │  existing conversation history
 └───────────┬───────────┘
             │
             ▼
 ┌───────────────────────┐
 │ 4. Engagement closure │  /close-engagement (or REPL exit):
 │    + chain mining     │  parse tool calls, classify outcome,
 │                       │  store experience
 └───────────────────────┘
```

## Data model

### Target profile

```python
{
  "host": "www.britimp.com.py",
  "resolved_ip": "54.69.84.63",
  "ports": [80, 110, 443, 993],
  "services": {"80": "http/apache", "443": "https/apache", "110": "pop3"},
  "tech": ["apache", "wordpress?"],     # from whatweb / nmap scripts
  "os_hint": "linux",                    # best guess
  "asn": "AS16509 AMAZON-02",            # optional
  "notes": "shared hosting with aldeatech",
}
```

### Experience record

```python
{
  "id": "eng_<uuid>",
  "created_at": "2026-04-12T02:18:00Z",
  "target_profile": { ... },             # as above
  "chain": [                             # ordered tool calls
    {"tool": "nmap",     "args": "-sV -sC -T4", "status": "ok"},
    {"tool": "whatweb",  "args": "https://...", "status": "ok"},
    {"tool": "gobuster", "args": "dir -u ...",  "status": "ok"},
    {"tool": "nuclei",   "args": "-t cves/",    "status": "ok"},
    ...
  ],
  "outcome": "partial",                  # success | partial | fail
  "outcome_signals": [                   # what we detected
    "shell_gained": false,
    "flag_found": false,
    "cve_confirmed": ["CVE-2024-XXXX"],
    "directories_found": 12,
  ],
  "agent_path": ["recon_scout"],         # agents that participated
  "duration_s": 320,
  "summary": "short text description",
}
```

The embedding goes over a **document** built from
`target_profile + summary + tools_used`, so similarity search finds
profiles with similar tech/port/outcome combinations.

### Storage

New ChromaDB collection: `kryon_experiences`, separate from
`kryon_knowledge`. Both use the same Ollama HTTP embedder
(`nomic-embed-text`).

Path: `/workspace/.kryon_knowledge/chromadb/` (same sqlite file,
different collection).

## Retrieval flow

When Recon Scout (or any recon-capable agent) identifies a target:

1. Build a preliminary profile (host + any known ports/tech).
2. Call `recall_similar_experiences(profile, k=3)`.
3. The tool returns a list of summaries like:
   > *"Previously against `AWS IP + Apache + WordPress + port 443`:
   >  nmap → whatweb → wpscan → credential-stuffing gave shell in 4m20s."*
4. The agent uses these as **hints**, not orders, to shape its plan.
   If prior chains show that step X was wasted on similar targets, skip
   it. If a specific tool combo worked fast before, try it first.

## Capture flow

`/close-engagement` command in the REPL:

1. Walk the current `conversation_input` / message history.
2. Extract every tool call + arguments + result excerpt.
3. Build a profile from the first successful scan (nmap or curl).
4. Classify outcome from signals:
   - Shell obtained → grep for `whoami`, `uid=`, shell prompts
   - Flag found → grep for `flag{`, `HTB{`, `THM{`
   - CVE confirmed → grep nuclei/searchsploit output for `CVE-`
   - Otherwise → `partial` or `fail`
5. Ask the user for a short `summary` line (optional, 1 prompt).
6. `add_experience(...)` persists the record.

Manual trigger first; auto-capture on exit can come later.

## REPL commands

| Command | Action |
|---|---|
| `/experiences` | List last N experiences with profile + outcome |
| `/experiences <id>` | Dump one full experience record |
| `/experiences search <query>` | Free-text similarity search |
| `/close-engagement [summary]` | Mine current session and save |

## Module layout

```
src/kryon/learning/
├── __init__.py            # public API: add_experience, recall,
│                          # build_profile, extract_chain
├── experiences.py         # ChromaDB store (add, query, list, get)
├── profiler.py            # target profile extractor
├── chain_extractor.py     # parse message history → tool chain +
│                          # outcome classification
└── README.md              # quick dev reference
```

Tools exposed to agents (in `src/kryon/tools/knowledge/`):

```
recall_similar_experiences(target_profile: dict, k: int = 3) -> list
```

## Metrics to track

v1 is a success if, over 10-15 engagements, we see:

- Median `duration_s` against similar profiles **decreasing**
- `outcome=success` rate **increasing**
- First attack-chain step reliably chosen from recalled chains
- Users (you) perceive Kryon as "remembering" prior work

We won't wire metrics dashboards in v1. Engagement logs already land in
`kryon-logs` volume; extracting metrics is a follow-up.

## Failure modes to watch

- **Garbage-in/garbage-out**: bad outcome classification poisons the store.
  Mitigation: user can delete experiences via `/experiences delete <id>`.
- **Profile drift**: two real-world targets with the same port list but
  completely different apps. Mitigation: include `tech` and `summary` in
  the embedding text so similarity is not purely ports-based.
- **Over-reliance on recall**: agent blindly follows a past chain that
  doesn't apply. Mitigation: prompt wording emphasizes "hints, not orders".

## v2 ideas (out of scope for this change)

- Failure memory ("this chain does not work against nginx+cloudflare")
- Automatic prompt patches when a new chain consistently outperforms the
  default playbook
- Cross-agent experience sharing (Pentest Agent reads Recon Scout experiences)
- Outcome auto-labeling via a small classifier model
- Time-decay on old experiences


---

# v2 — Closed loop (Fases 1+2+3)

> Status: shipped 2026-04-29
> Owner: skyvanguard
> Test count: 231 dedicated to learning loop, all green

v1 captured engagements but the loop never came back to influence anything.
v2 closes that loop in three layers:

```
   v1: engagement ──→ experience store ──→ recall on next engagement
       (capture only)

   v2: engagement ──→ experience store
                              │
       ┌──────────────────────┼──────────────────────┐
       │                      │                      │
       ▼                      ▼                      ▼
   F1: Drafting          F2: Scoring             F3: Auto-creation
   (single→draft)        (corpus→ranking)        (cluster→eval→draft)
```

## Layer F1 — Skill drafting (human-in-the-loop)

**Trigger**: every engagement with `outcome ∈ {success, partial}` and chain
length ≥ 2 produces a draft markdown skill in `~/.kryon/drafts/`.

**Pipeline**:
1. `auto_extract_on_exit()` (REPL exit handler) saves the experience.
2. `_try_synthesize_skill_draft()` calls `synthesize_draft(experience)`.
3. `try_synthesize_and_persist()` writes `<name>.md` to drafts dir.

**REPL commands**:

| Command | What it does |
|---|---|
| `/skill drafts` | List drafts pending review (name + outcome + source experience) |
| `/skill review <name>` | Render the draft body for inspection |
| `/skill promote <name>` | Move draft → `playbooks/_drafts/` for staging |
| `/skill discard <name>` | Delete the draft permanently |

**Critical**: `playbooks/_drafts/` is **ignored** by `SkillLoader.scan()` —
the underscore prefix marks the dir as inactive. Promotion to production
still requires the operator to hand-edit + move out of `_drafts/`.

**Files involved**:
- `src/kryon/learning/skill_synthesizer.py` — templating
- `src/kryon/learning/draft_writer.py` — filesystem IO
- `src/kryon/services/auto_extract.py` — auto-trigger on REPL exit
- `src/kryon/repl/commands/skill.py` — REPL commands

## Layer F2 — Scoring + bandit-lite ranking

**Goal**: when two skills both match a turn's keywords, pick the one with
better track record without a human re-ordering `priority:` fields by hand.

**Pipeline**:
1. `score_skills(experiences, skill_names)` aggregates per-skill stats
   (success/partial/fail counts, win rate, Wilson 95% lower bound).
2. `SkillLoader.match()` accepts a `ranking` arg with four modes:
   - `priority` (default) — pure priority sort, exactly v1 behaviour.
   - `hybrid` — priority is tier-1 sort, Wilson lower bound breaks
     ties within tiers.
   - `dual` (F77.G.5) — priority tier-1, **combined Wilson + reusability**
     score breaks ties. See "F77.G.5 dual-reward" section below.
   - `score` — score-only ranking; experimental, not banking-safe.
3. Activation: env var `KRYON_SKILL_RANKING=hybrid|dual` (off by default
   for regulated audits — priority remains deterministic).

**Wilson lower bound** keeps a 5/5-cold-starter from leapfrogging an
80/100-veteran. Skills with sample < 10 are flagged `is_low_confidence`
and fall back to priority-only within their tier.

**Telemetry**: `~/.kryon/selection_log.jsonl` records every match
decision (hashed user_msg, ranking mode, candidates, selected). Plaintext
logging is opt-in via `KRYON_SELECTION_LOG_PLAINTEXT=1` (banking privacy
posture is hashed-by-default).

**REPL command**:

| Command | What it does |
|---|---|
| `/skill scores` | Leaderboard with win rate, Wilson lower bound, last used |

**Files involved**:
- `src/kryon/learning/skill_scorer.py` — Wilson + ranking helpers
- `src/kryon/learning/selection_telemetry.py` — JSONL log
- `src/kryon/skills/loader.py` — `match()` extended with ranking arg

## Layer F3 — Autonomous skill creation with eval gate

**Trigger**: manual via `/skill auto detect` (no cron — operator decides
when to run). Scans the experience corpus for clusters of similar
engagements (≥ 3 by default) and proposes one draft per cluster.

**Pipeline**:
1. `detect_recurrent_chains(experiences)` — Jaccard on bigrams +
   profile tech overlap → `ChainCluster` objects with deterministic ids.
2. `synthesize_from_cluster(cluster, llm_caller=...)` — frontmatter is
   100% deterministic; body is templated, optionally refined by an LLM
   that only sees a constrained prompt. **Hallucinated tool names are
   rejected** (validator checks every backtick / underscore identifier
   against `required_tools`).
3. `evaluate_draft_against_corpus(draft, cluster, findings)` — heuristic
   gate: would the draft's chain have detected the historical findings
   that match the cluster's profile? Returns `passed` / `rejected` /
   `skipped` (precision-over-recall posture: when in doubt, skip).
4. Output split:
   - **passed** → `~/.kryon/drafts/_auto/<name>.md` + `.eval.json` sidecar
   - **rejected / skipped** → `~/.kryon/drafts/_rejected/<name>.md` + sidecar

**REPL command**:

| Command | What it does |
|---|---|
| `/skill auto detect` | Run the full pipeline; print summary |
| `/skill auto status` | List drafts in `_auto/` and `_rejected/` with eval reasons |

**CWE → tools map** (used by `evaluate_draft_against_corpus`):

The default map (`_DEFAULT_CWE_TO_TOOLS`) covers ~30 CWEs with real
Kryon tool names (`sqlmap_scan`, `nuclei_scan`, `bloodhound_collect`,
`kerberoast`, etc.). Customize without code edits via:

- `~/.kryon/cwe_map.yaml` (default lookup)
- `KRYON_CWE_MAP=/path/to/file.yaml` (env override)
- `evaluate_draft_against_corpus(..., cwe_to_tools={...})` (programmatic)

See `docs/examples/cwe_map.yaml` for syntax + commented examples.

Per-CWE entries in the file **replace** the default for that CWE (no
within-CWE union — your team is the authority on what tools you trust).
New CWEs in the file extend the map.

**Files involved**:
- `src/kryon/learning/pattern_detector.py` — clustering
- `src/kryon/learning/skill_synthesizer.py` — `synthesize_from_cluster`
- `src/kryon/learning/skill_evaluator.py` — eval gate + CWE map
- `src/kryon/learning/auto_pipeline.py` — orchestrator

## Environment variables

| Var | Effect |
|---|---|
| `KRYON_SKILL_RANKING` | `priority` (default) / `hybrid` / `dual` / `score` |
| `KRYON_SKILL_RANKING_WILSON_WEIGHT` | (informational; weights live in scorer code) |
| `KRYON_DRAFTS_DIR` | Override `~/.kryon/drafts/` |
| `KRYON_SELECTION_LOG` | Override `~/.kryon/selection_log.jsonl` path |
| `KRYON_SELECTION_LOG_DISABLE` | `1` skips telemetry writes |
| `KRYON_SELECTION_LOG_PLAINTEXT` | `1` stores user_msg verbatim (default: SHA-256 only) |
| `KRYON_CWE_MAP` | Path to a yaml CWE → tools override |
| `KRYON_EXPERIENCES_DIR` | (v1) override ChromaDB persist path |
| `KRYON_EMBEDDING_BASE_URL` | (v1) Ollama URL for embeddings |

## Filesystem layout

```
~/.kryon/
├── chromadb/                         # v1 experience store (kryon_experiences)
├── drafts/
│   ├── <name>.md                      # F1 — pending operator review
│   ├── _auto/<name>.md                # F3 — passed eval gate
│   ├── _auto/<name>.eval.json         # eval report sidecar
│   ├── _rejected/<name>.md            # F3 — failed/skipped eval
│   └── _rejected/<name>.eval.json
├── selection_log.jsonl               # F2 — per-turn ranking decisions
└── cwe_map.yaml                      # F3 — operator-supplied override (optional)

src/kryon/skills/playbooks/
├── _drafts/                           # operator promoted; loader IGNORES
└── <regular dirs>                     # active skills (loaded normally)
```

## Test commands

```bash
# Pure tests (no chromadb required) — should always pass.
pytest tests/learning/

# With chromadb extra — tests that hit a real persistence layer come
# alive. They use tmp_path so don't pollute the user's ~/.kryon.
uv sync --extra rag
pytest tests/learning/

# Just the auto-creation pipeline (Fase 3):
pytest tests/learning/test_pattern_detector.py \
       tests/learning/test_synthesize_from_cluster.py \
       tests/learning/test_skill_evaluator.py \
       tests/learning/test_auto_pipeline.py \
       tests/learning/test_auto_e2e.py
```

## F77.G.6 — AutoSkill merge-ternary decision (arxiv 2603.01145)

### Why

`auto_pipeline` previously synthesized a fresh draft for every cluster
the pattern detector surfaced. On real corpora that means three
different `auto_web_pentest_*.md` files describing overlapping chains
all end up in `~/.kryon/drafts/`. AutoSkill's contribution is to gate
synthesis with a ternary triage step:

  - **ADD** — cluster is semantically new; synthesize a fresh draft.
  - **MERGE** — cluster overlaps an existing auto-skill enough to
    propose a versioned `.vN+1` of that skill instead. The original
    is NEVER overwritten.
  - **DISCARD** — cluster is degenerate (too small, low outcome) or
    sits in the ambiguous similarity band — skip silently instead of
    diluting the draft pool.

### Decision tree

```
1. cluster.sample_size < 3              → DISCARD (quality floor)
2. cluster.avg_outcome_score < 0.4      → DISCARD (quality floor)
3. existing pool is empty               → ADD
4. max similarity ≥ 0.80                → MERGE against argmax (v+1)
5. 0.50 ≤ max similarity < 0.80         → DISCARD (ambiguous band)
6. max similarity < 0.50                → ADD
```

Similarity is the same `0.7 * chain + 0.3 * tech` blend that
`pattern_detector._combined_similarity` uses, so the numbers are
comparable across both modules. Thresholds are configurable via
`decide_merge_action(merge_threshold=..., discard_band_lo=...)`.

### Banca-safety

- **MERGE never overwrites a promoted playbook.** It writes a NEW
  `.vN.md` draft in `~/.kryon/drafts/_auto/`. The operator inspects
  the diff, runs the existing tests, and promotes manually if (and
  only if) the v2 supersedes v1.
- The decider only sees auto-generated drafts (those with a
  `_provenance` frontmatter block). Hand-written drafts and core
  playbooks are outside the comparison set — the operator owns them.
- DISCARD is silent on the user-facing surface but logged at INFO
  with the reason chain, so `/skill auto detect --explain` can
  surface why a cluster was dropped.

### Lineage on a merged draft

When `auto_pipeline` writes a merged `.v2` draft, `_provenance` gains:

```yaml
_provenance:
  merge_from: pci-dss-audit          # base name of the merged-against skill
  merge_from_version: 1              # previous version
  merge_similarity: 0.92             # combined similarity score
```

This lets a curator running `gh pr diff` understand at a glance why
the new draft exists and what it claims to supersede.

### Activation

Always-on as of F77.G.6 — there's no opt-out env var. The decider's
default thresholds preserve the legacy ADD-everything behaviour
when the existing pool is empty (cold start). The MERGE path only
fires when at least one existing draft has `_provenance.representative_chain`
in its frontmatter — pre-F77.G.6 drafts that lack this field are
treated as hand-edited and excluded from comparison, so legacy
corpora upgrade gracefully.

## F77.G.5 — Dual-reward ranking (SAGE: arxiv 2512.17102)

### Why

Wilson-only ranking captures "how often does this skill succeed?" but
ignores "how often does the operator's matcher actually pick it up?".
A skill with a tight Wilson interval is well-validated; a skill that
also gets *re-selected across distinct engagements* is validated **AND**
broadly useful. SAGE (arxiv 2512.17102) shows that combining these two
signals gives faster, more stable skill evolution than either axis
alone — drafts validated in 2-3 similar engagements get promoted
sooner, and "one-hit wonders" that crushed a single CTF but never
re-appeared get pushed below their priority floor.

### How

The combined score is a weighted blend:

```
combined_score = w_wilson * wilson_lower_bound + w_reuse * reusability_norm
                                   (default 0.7)              (default 0.3)
```

- `wilson_lower_bound`: 95% Wilson lower bound on the success rate
  (unchanged from F77.G F2).
- `reusability_norm`: per-skill count of distinct selection-log records
  where the skill was selected, divided by the corpus max. Values are
  in [0, 1].

The 70/30 weighting deliberately keeps **correctness > popularity** for
banking compliance: a skill the operator happens to invoke a lot but
that fails 40% of the time still ranks below a quieter skill with a
tight Wilson interval. Operators can override the weights via
`score_skills(..., wilson_weight=..., reuse_weight=...)` for offline
experiments.

### Banking-safety contract

Same as hybrid: **priority is the primary sort** in `rank_skills_dual`.
A high-combined-score skill at priority 50 NEVER outranks a
low-combined-score skill at priority 10. The combined score only
orders within a priority tier. This is enforced by
`test_dual_ranker_respects_priority_tiers` so a refactor that breaks
the contract can't be merged.

### Activation

```bash
export KRYON_SKILL_RANKING=dual
```

Off by default — the matcher uses priority-only ranking unless the
operator explicitly opts in. When telemetry is missing (fresh install,
selection log cleared), dual ranking degrades gracefully to
Wilson-only via the `telemetry_records=None` path.

### Edge cases pinned

| Case | Behaviour | Test |
|---|---|---|
| No telemetry passed | reusability fields = 0 → combined collapses to `0.7 * wilson` | `test_score_skills_without_telemetry_is_legacy_path` |
| Skill in telemetry but no experiences | sample=0, Wilson=0, combined = `0.3 * reuse_norm` | `test_zero_engagement_skill_with_reusability` |
| Low-confidence skill (sample < 10) | Wilson contribution suppressed (treated as 0); only reuse contributes | `test_low_confidence_skill_suppresses_wilson_in_combined` |
| Same priority + dual ranking | combined_score breaks tie, NOT Wilson alone | `test_dual_and_hybrid_diverge_on_reuse_tie_break` |
| Cross-priority + dual ranking | Priority ALWAYS wins (banca-safe) | `test_dual_ranker_respects_priority_tiers` |

## F77.G.4 — Guide gate (relevance + naturalness)

A textual second-axis filter on auto-generated drafts, layered on top of
the F3 technical eval. Inspired by SGS (https://arxiv.org/abs/2604.20209),
which showed that a Guide role scoring synthetic problems for *quality*
+ *relevance* prevents the Conjecturer from collapsing into reward-hacked
nonsense. Applied here: even a draft that passes the CWE→tools eval can
still be textually broken (mismatched frontmatter/body, placeholder soup,
loop artifacts). The Guide catches that for free.

### What it scores

`src/kryon/learning/guide_scorer.py` — two axes, weighted average,
zero LLM calls (stdlib regex only):

- **`relevance` (weight 0.6)** — coherence frontmatter ↔ body. Penalties
  for tools in `required_tools:` not mentioned in body, missing
  Steps/Playbook/Detection section, empty body or empty
  `required_tools:`.
- **`naturalness` (weight 0.4)** — generative-loop / stub artifacts.
  Penalties for length out of 200..20000 chars, high placeholder
  density (TODO, XXXX, `{ALL_CAPS}`), repeated identical lines beyond
  25%, empty fenced code blocks.

`combined = 0.6 * relevance + 0.4 * naturalness`. Default threshold
**0.6** to pass. Banking-safe rollout — empirically validated to give
zero false positives against the 107 hand-written playbooks shipped in
`src/kryon/skills/playbooks/` (lowest real playbook scores 0.60, highest
1.00).

### Activate

The gate is **off by default** (banking-safe). Activate via:

```bash
# Per-process env flag (preferred)
export KRYON_GUIDE_GATE=true
export KRYON_GUIDE_THRESHOLD=0.6   # optional override

# Or programmatically (e.g. in tests)
from kryon.learning.skill_evaluator import evaluate_draft_against_corpus
evaluate_draft_against_corpus(..., apply_guide_gate=True)
```

When active, `EvalReport.eval_status` can take a new value
`rejected_by_guide` and the technical eval is short-circuited (no
findings walk). The report's `guide_score` field carries
`{relevance, naturalness, combined, reasons}` for the operator to see
WHY a draft was kicked out.

### Test it yourself against your own drafts

```bash
python -c "
from pathlib import Path
import yaml
from kryon.learning.guide_scorer import score_draft

class _D:
    def __init__(s, b, fm): s.body, s.frontmatter, s.name = b, fm, 'x'

for p in Path('~/.kryon/drafts/_auto').expanduser().rglob('*.md'):
    raw = p.read_text(encoding='utf-8')
    end = raw.find('---', 3)
    fm = yaml.safe_load(raw[3:end]) or {}
    body = raw[end+3:].lstrip()
    s = score_draft(_D(body, fm))
    flag = 'PASS' if s.passes() else 'FAIL'
    print(f'{flag}  {s.combined:.2f}  {p.name}')
    for r in s.reasons:
        print(f'         - {r}')
"
```

### Why opt-in (not default-on yet)

The 107-playbook regression confirms 0% false positives in the hand-
written corpus, but real auto-drafts (under 50 in production at time of
writing) are too small a sample to flip the default. Once we have ≥ 200
auto-drafts evaluated with the gate ON via env, and the false-rejection
rate stays under 5%, Fase 4 of F77.G.4 flips the default.
