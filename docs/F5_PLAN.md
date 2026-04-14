# F5 — Extended Reasoning + Industrial Pattern Coverage

> **Target:** Kryon v2.3.0 "Harvester"
> **Driver:** move from "hand-written 20 regex patterns + constrained LLM"
> to "1500+ industry rules + LLM with full reasoning budget"
> **Honest premise:** the ceiling we hit in the 10 LLM hunts was partly
> self-inflicted (turn/commit constraints I added) and partly due to
> threadbare pattern coverage. Remove both bottlenecks before blaming
> the model.

---

## 0. Baseline evidence

| Metric | Current state | Gap / cause |
|---|---|---|
| `KRYON_HUNT_MAX_TURNS` | 15 | Artificial — Mythos / ARTEMIS ran hundreds of turns |
| "Commit early" rule | Forces hypothesis after 2 reads | My overcorrection after hunt #4 |
| Escape hatch | ≥ 6 turns → NO FINDING | Triggers before model has time to reason |
| Pattern library | ~20 regexes in `priority.py` | Semgrep ships 1500+ CWE-labeled rules |
| Benchmark coverage | None vs established suite | We can't tell if we're improving |
| PoCs generated | Pattern-mirror (not target-aware) | No CWE-specific harness templates |

**What works that stays:** HunterPool, validator 3-phase, CVE corpus (297 entries), `/hunt`, `/corpus`, `forbidden_tools` veto, session compaction, heuristic fallback.

---

## 1. Phases

### F5.1 — Extended reasoning ( ~2-4 hours )

Revert my own constraints + add introspection loops.

**F5.1.a** Lift turn/time budgets
- `KRYON_HUNT_MAX_TURNS` default 15 → **50**
- `KRYON_HUNTER_TIMEOUT_S` default 900 → **1800** (30 min)
- `KRYON_LLM_HUNTER_TIMEOUT_S` default follows
- Escape hatch threshold ≥ 6 → **≥ 20** (only triggered on truly stuck runs)
- Remove `commit-early: at most 2 read_function` rule from playbook

**F5.1.b** Phase 2.5 — Reflection turn (playbook)
Every 5 turns the hunter MUST emit a `REFLECT` block:
```
REFLECT
  Current hypothesis: <cwe + function + trigger>
  Evidence FOR:       <what I've read that supports it>
  Evidence AGAINST:   <what I've read that could disprove it>
  What would kill it: <concrete input that should NOT crash if the hypothesis is wrong>
  Next action:        <one tool call>
```
Not emitted → warning in telemetry; emitted but contradictions ignored → validator flags.

**F5.1.c** Phase 3.5 — Adversarial self-challenge
Before emitting a FINDING, the hunter MUST construct a "safe" PoC with input that SHOULD NOT crash according to the hypothesis, run it, and verify no crash. If it crashes too → hypothesis wrong or over-broad; revise.

**F5.1.d** New tool: `reflect_on_hypothesis`
Optional tool that captures the REFLECT block as structured data, appended to the hunter's findings as `_reflections[]`. Useful for post-hoc debugging even if the final FINDING isn't emitted.

**Deliverable**: hunt re-run with new budget + reflection rule. Expect higher turn counts, structured REFLECT records in telemetry.

---

### F5.2 — Semgrep integration ( ~3-5 hours )

Semgrep is the industry standard for AST-level pattern matching. ~1500 community rules across C/C++, Python, JS/TS, Go, Java, Ruby, PHP. Used in production at Slack, Snowflake, Stripe, Snowflake, Firefox, etc.

**F5.2.a** Install semgrep in the kryon container
- Add to `docker/Dockerfile`: `pip install semgrep==<pinned>` (~50 MB)
- Fetch the free community rule packs: `p/security-audit`, `p/owasp-top-ten`, `p/secrets`, `p/r2c-security-audit`, `p/cwe-top-25`, `p/c`, `p/cpp`
- Cache rules under `/workspace/.semgrep_rules`

**F5.2.b** New tool: `semgrep_scan`
```python
@function_tool
def semgrep_scan(
    repo_path: str,
    rulesets: str = "p/security-audit,p/cwe-top-25",
    severity_min: str = "WARNING",   # INFO | WARNING | ERROR
    max_findings: int = 50,
) -> str:
    """Run semgrep against a repo and return structured findings:
       {path, line, cwe, rule_id, severity, message, snippet}"""
```
- Invoke: `semgrep --json --config=<rulesets> --severity=WARNING+ <path>`
- Parse JSON output, extract findings, cap at `max_findings`
- Register in tool_budget + add to zero-day-hunter.md `required_tools`

**F5.2.c** New runner: `SemgrepHunter`
Like HeuristicHunter but uses semgrep as the source of candidates:
1. `semgrep_scan` on the file → list of rule hits (real CWE labels)
2. For each hit, generate a CWE-specific PoC (templates from F5.4)
3. `run_sandboxed` each PoC
4. Attach `_semgrep_rule_id`, `_semgrep_message` provenance

**F5.2.d** Hybrid hunt mode: `--runner hybrid`
Staged pipeline:
1. SemgrepHunter runs first (fast, high coverage, high FPR)
2. Filter: keep only hits above `severity_min` with nearby data-flow evidence
3. LLM hunter investigates the survivors (cheaper — 5-10 candidates vs 75 files)
4. Validator triages LLM findings

This uses semgrep's breadth + LLM's depth. Industry pattern (used by DeepCode, Pixee, etc).

**Deliverable**: `/hunt <repo> --runner semgrep` and `--runner hybrid` working. Measured on zlib: expect 20-40 semgrep hits, 5-10 post-filter candidates for LLM.

---

### F5.3 — Juliet Test Suite benchmark ( ~3-4 hours )

**Juliet C/C++ 1.3** (NIST, ~64k test cases, labeled by CWE).
- `good/` and `bad/` variants per CWE
- Known flawed patterns = ground truth
- Standard benchmark for static analyzer coverage

**F5.3.a** Harness
```python
scripts/bench_juliet.py
  --runner {heuristic, semgrep, hybrid, llm}
  --cwes 787,416,190,125,476,121,415
  --max-cases 200  # per CWE
```
For each `(cwe, case)` pair:
1. Run the runner on `bad/` variant → record finding presence/absence
2. Run on `good/` variant → record false positive presence

**F5.3.b** Metrics
- **Recall@CWE**: % of flawed cases where the runner flagged the bug
- **FPR@CWE**: % of clean cases where the runner flagged something
- **Per-rule attribution**: which semgrep rules / heuristic patterns actually fire

**F5.3.c** Acceptance criteria
| Runner | Target recall@top-5-CWEs | Target FPR |
|---|---|---|
| heuristic | ≥ 30% | ≤ 20% |
| semgrep | ≥ 60% | ≤ 15% |
| hybrid | ≥ 70% | ≤ 10% |
| llm (with F5.1) | ≥ 50% | ≤ 15% |

If `hybrid ≥ 70% recall, ≤ 10% FPR`, Kryon is **benchmark-competitive with
commercial SAST tools** on industry-standard pattern matching.

**F5.3.d** Report artifact: `docs/BENCHMARKS.md` updated per run, plotted comparison chart.

---

### F5.4 — Curated pattern library ( iterative, starts ~4 hours )

For the top 25 CWEs (by prevalence in MITRE 2024), provide:

```yaml
# src/kryon/skills/patterns/cwe-787.yaml
cwe: CWE-787
name: Out-of-bounds Write
detect_patterns:
  - regex: "\\bmemcpy\\s*\\([^,]+,[^,]+,[^)]+\\)"
    lang: c
    confidence: medium
  - semgrep_rule: rules.cpp.buffer-overflow.memcpy-unsafe-size
  - semgrep_rule: rules.c.security-audit.insecure-use-strcpy
trigger_templates:
  - stdin_bytes: "A" * 1024  # classic overflow
  - stdin_bytes: "\xff" * 65536  # large buffer
poc_skeleton: |
  #include <string.h>
  extern void TARGET_FN(const char *);
  int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
      if (size < 4) return 0;
      TARGET_FN((const char*)data);
      return 0;
  }
fallback_poc: |
  #include <stdlib.h>
  #include <string.h>
  int main(void) {
      char *p = malloc(SIZE_SMALL);
      memcpy(p, ATTACKER_INPUT, SIZE_LARGE);
      return p[0];
  }
escalation_hints:
  - "If OOB write, check adjacent allocations for function pointers or return addresses"
  - "If OOB read, check if leaked bytes include secrets or pointers"
```

**F5.4.a** Create `src/kryon/skills/patterns/` directory with 25 YAML files
**F5.4.b** Loader that reads the YAML, merges into HeuristicHunter's pattern set
**F5.4.c** For each CWE, ensure the semgrep rules referenced actually exist in our cached ruleset

**Priority order** (by MITRE 2024 top-25):
CWE-787, 416, 20, 125, 78, 22, 79, 190, 476, 502, 863, 276, 918, 77, 798, 306, 362, 119, 732, 287, 400, 352, 269, 94, 434

---

## 2. Dependencies + execution order

```
F5.1 Extended reasoning  ──┐
                           ├── independent, both can start now
F5.2 Semgrep integration ──┘
        │
        └── F5.3 Juliet benchmark  (blocks on F5.1 + F5.2)
                │
                └── F5.4 Pattern library  (informed by F5.3 gap analysis)
```

**Parallel work slots**:
1. Developer A: F5.1 (playbook + env vars + reflection tool)
2. Developer B: F5.2 (semgrep install + tool + runner)
3. Sequential: F5.3 benchmark, then F5.4 iterative pattern additions

Single-developer (this session): F5.1 → F5.2 → F5.3 → F5.4 iteratively.

---

## 3. Configuration knobs added

```bash
# Extended reasoning
KRYON_HUNT_MAX_TURNS=50
KRYON_HUNTER_TIMEOUT_S=1800
KRYON_HUNT_REFLECTION_EVERY=5   # emit REFLECT every N turns
KRYON_HUNT_ESCAPE_THRESHOLD=20  # escape hatch after N turns w/o crash

# Semgrep
KRYON_SEMGREP_RULESETS="p/security-audit,p/cwe-top-25,p/c,p/cpp"
KRYON_SEMGREP_SEVERITY_MIN="WARNING"
KRYON_SEMGREP_MAX_FINDINGS=100

# Hybrid
KRYON_HYBRID_POST_FILTER_MIN_SEVERITY="WARNING"
KRYON_HYBRID_MAX_LLM_CANDIDATES=10   # cap LLM invocations
```

---

## 4. Acceptance criteria for F5 as a whole

- [ ] LLM hunt with 50-turn budget + reflection produces at least ONE
      run with structured FINDING from gemma4 OR qwen3-coder
      (proving the ceiling wasn't the model size but the constraints)
- [ ] `semgrep_scan` tool registered; `SemgrepHunter` runner works
- [ ] `/hunt <repo> --runner semgrep` produces >= 10 findings on zlib
      with real CWE labels
- [ ] `/hunt --runner hybrid` produces findings with both
      `_semgrep_rule_id` and LLM validation evidence
- [ ] `scripts/bench_juliet.py` runs against a sample of 500 Juliet
      cases (top 5 CWEs x 100 each)
- [ ] `docs/BENCHMARKS.md` reports recall + FPR per runner
- [ ] 25 CWE pattern files exist under `skills/patterns/`
- [ ] Hybrid runner recall ≥ 70% on Juliet top-5 CWEs

---

## 5. What this lets us claim honestly

After F5, Kryon becomes defensible on three dimensions:

1. **Coverage** — semgrep's 1500+ industry rules + curated CWE library.
   No longer "handful of regexes" vs commercial SAST.
2. **Measurable** — Juliet benchmark gives recall/FPR numbers. Anyone
   can reproduce. Bullshit threshold cleared.
3. **Model-agnostic reasoning** — if the LLM CAN close the H→V→R loop
   autonomously, the extended reasoning budget lets it. If it can't
   (capability ceiling of the specific model), the hybrid mode still
   delivers via semgrep breadth.

The sentence we earn the right to say:

> "Kryon finds issues with industry-standard coverage (semgrep +
> curated CWE patterns), validates them with ASAN, and optionally
> invokes an LLM for deeper reasoning. On Juliet Test Suite,
> recall@top-5-CWEs is [X]% with [Y]% FPR."

Measurable. Defensible. Local-only. No cherry-picking.

---

## 6. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Semgrep adds ~50 MB + Python deps | Already inside Docker; isolated |
| Juliet test suite is 500 MB | Download once, persist in volume |
| LLM still doesn't converge at 50 turns | Hybrid mode wraps it — fallback still works |
| Reflection prompt makes model too verbose | Cap reflections at 500 chars; warning in prompt |
| Pattern library YAML proliferates bugs | CI check: every YAML must validate against schema |
| Semgrep false positives overwhelm validator | Hybrid pre-filter by severity + source reachability |

---

## 7. Open questions (for us, before coding)

1. Do we want `semgrep_scan` exposed to the LLM hunter as a **tool it
   can call**, or only used by the SemgrepHunter runner?
   *Recommendation: both. Let LLM call it for targeted re-runs on
   smaller scope.*
2. Should `forbidden_tools` also block `semgrep_scan` when the hunter
   is in LLM-only mode?
   *Recommendation: no — it's passive (no code execution), safe as
   ambient tool.*
3. How much of Juliet do we benchmark per commit?
   *Recommendation: ~500 cases for CI, full 64K for nightly /
   research runs.*

Ready to arrancar por **F5.1 + F5.2 en paralelo**. Confirmar y empezar.
