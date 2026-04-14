# F6 — Push Juliet recall to 100% (or as close as physics allows)

> **Target:** Kryon v2.4.0 "Coverage"
> **Goal:** Drive recall@CWE on Juliet C/C++ from current 0-27%
> to **≥ 90% on top-10 CWEs**, while keeping FPR < 15%.
> **Honest stretch goal:** 100% recall on patterns that are statically
> detectable. Some CWEs need data-flow analysis we don't have — those
> are documented as F7 (later).

---

## 0. Calibration — what's realistic

Commercial SAST baselines on Juliet (public papers + vendor whitepapers):

| Tool | Top-CWE recall | FPR | Cost |
|---|---|---|---|
| **Coverity** | 70-80% | 8-15% | $100K+/year |
| **Klocwork** | 60-75% | 10-18% | $80K+/year |
| **Veracode** | 50-65% | 12-20% | cloud subscription |
| **Semgrep Pro** | 60-70% | 5-12% | subscription |
| **Semgrep OSS** (current Kryon) | 13-27% | 7% | free |
| **Kryon heuristic** (current) | 33-73% | 67% | free, **noisy** |
| **Kryon hybrid** (current) | 13-27% | 7% | free |

Kryon today is in "free OSS tier". F6 target: **enter commercial tier** —
70-90% recall + < 15% FPR. 100% recall is a stretch target; some Juliet
test cases require flow-sensitive analysis (taint propagation across
function boundaries through return values) that our static patterns
can't cover without significant infra.

---

## 1. Why the current numbers are low — gap diagnosis

From `bench_juliet.json` first run:

| CWE | recall@any | gap diagnosis |
|---|---|---|
| CWE-121 | heuristic 73%, semgrep 20% | semgrep rules thin; heuristic over-matches |
| CWE-122 | heuristic 73%, semgrep 20% | same as 121 |
| CWE-190 | heuristic **0%**, semgrep 27% | NO heuristic pattern for int overflow |
| CWE-416 | heuristic 33%, semgrep 13% | UAF pattern weak in both |
| CWE-476 | heuristic **0%**, semgrep **0%** | NO pattern at all for null deref |

And FPR proxy on zlib (clean code):
- heuristic: 67% (15 findings on 15 files) → way too aggressive
- semgrep: 7% (1/15) → fine
- hybrid: 7% (matches semgrep)

**The two killers are:**
1. **Missing patterns** — entire CWE classes have zero coverage
2. **Heuristic FPR** — fires on benign memcpy/strcpy that's properly bounded

Both are fixable.

---

## 2. F6 Phases

### F6.1 — Custom Semgrep rules per CWE (the highest-leverage move)

Semgrep accepts custom YAML rules. We write a Kryon-specific ruleset
tuned for Juliet's BadSink patterns.

**Action:**
- New dir: `src/kryon/skills/patterns/semgrep/` with one YAML per CWE
- Mount the path into `_DEFAULT_RULES_ROOT` alongside the upstream
  `semgrep-rules/` so both are loaded
- For each top-10 CWE, write 3-5 rules covering Juliet template variants

**Per-CWE rule strategy** (reading Juliet bad-function templates):

| CWE | BadSink template | Custom rule pattern |
|---|---|---|
| 121 stack overflow | `char buf[N]; strcpy(buf, attacker)` | match `char $BUF[$SIZE]; ... strcpy($BUF, $X)` where $X traces to BadSource |
| 122 heap overflow | `char *p = malloc(N); memcpy(p, src, M)` | match `$P = malloc($SIZE); ... memcpy($P, $SRC, $LEN)` where $LEN > $SIZE statically |
| 190 int overflow | `n + m` where both attacker-controlled | match `$X + $Y` patterns flowing into malloc/array/loop |
| 415 double free | `free(p); ... free(p)` | match two `free($P)` calls on same variable in same scope |
| 416 UAF | `free(p); ... use *p` | match `free($P); ... $P->...` or `... *$P` |
| 476 null deref | `p = NULL; ... p->x` | match `$P = NULL; ... $P->` |
| 78 cmd injection | `system(buf)` where buf has user input | match `system($X)` / `popen($X)` / `execl*($X, ...)` with attacker source |
| 119 bounds | generic out-of-bounds | catch-all for `arr[$I]` where $I unbounded |
| 134 format string | `printf(buf)` no format | match `printf($X)` where $X != literal |
| 415 double free | covered above | — |

**Acceptance criteria:** semgrep recall on top-10 CWEs ≥ 70%.

**Effort:** 1-2 days. Each rule is ~10-30 lines YAML.

---

### F6.2 — Heuristic pattern expansion

Add patterns for the CWEs the heuristic currently misses (190, 476).

**Patterns to add to `priority.py`** (or extract to YAML library):

```yaml
CWE-190 int overflow:
  - r"\b(\w+)\s*\+\s*\w+\s*\)"               # a + b in arg position
  - r"\b(\w+)\s*\*\s*\w+\s*\)"               # a * b in arg position
  - r"malloc\s*\(\s*\w+\s*[\+\*]\s*\w+\s*\)" # alloc with arithmetic
  - r"memcpy\s*\([^,]+,[^,]+,\s*\w+\s*[\+\*]\s*\w+" # memcpy size arithmetic
  - PoC template: alloc with int math, demo OOB

CWE-476 null deref:
  - r"\b(\w+)\s*=\s*NULL\s*;.*?\1\s*->"  # NULL assign then deref
  - r"\b(\w+)\s*=\s*NULL\s*;.*?\*\1"     # NULL then star-deref
  - r"if\s*\(\s*!\s*\w+\s*\)\s*\{[^}]*\}\s*\1\s*->" # null-check guarded then deref outside
  - PoC template: explicit null+deref crash

CWE-415 double free:
  - r"free\s*\(\s*(\w+)\s*\).*?free\s*\(\s*\1\s*\)"
  - PoC template: alloc + free + free

CWE-78 command injection:
  - r"system\s*\([^)]*(?!\".*\"\s*\))"  # system() with non-literal
  - r"popen\s*\([^)]*(?!\".*\")"
  - r"exec[lv]p?\s*\([^)]*(?!\".*\")"
  - PoC template: system(user_input)

CWE-134 format string:
  - r"printf\s*\(\s*\w+\s*\)"            # printf(var) — no format
  - r"fprintf\s*\([^,]+,\s*\w+\s*\)"
  - PoC template: printf with %n
```

**Acceptance criteria:** heuristic recall on CWE-190 ≥ 50%, CWE-476 ≥ 40%.

**Effort:** ~1 day to write + tune.

---

### F6.3 — FPR reduction (context-aware filtering)

Heuristic FPR = 67% on zlib means it's flagging legitimate bounded calls.

**Tactics:**

1. **Skip patterns inside `if (size < N)` blocks** — the bound is right there
2. **Skip patterns where source is a string literal** — `strcpy(buf, "hello")` is safe
3. **Skip patterns inside `static` const-context functions** — they don't take attacker input
4. **Require attacker-controlled source for high-confidence finding** — taint-style:
   - if param is `argv[]` / `getenv` / `recv` / `read(0,...)` → high confidence
   - if no such source nearby → demote to "pattern-only" verdict
5. **Skip well-known safe wrappers** — `zmemcpy` (zlib), `g_strdup` (glib), etc.

**Acceptance criteria:** heuristic FPR on zlib ≤ 20% (down from 67%).

**Effort:** 0.5 day.

---

### F6.4 — CWE label normalization

Currently:
- Heuristic emits CWE-787 for everything
- Semgrep emits CWE-14 for memset, CWE-676 for strcpy, etc.
- Juliet uses CWE-121, 122, 190, 416, 476

Build a normalization map that translates ALL detection-CWEs to the
**most specific Juliet-compatible CWE** before comparison. Examples:

```python
CWE_ALIAS_MAP = {
    "CWE-787": ["CWE-121", "CWE-122", "CWE-124", "CWE-787"],  # OOB write family
    "CWE-125": ["CWE-126", "CWE-127", "CWE-125"],              # OOB read family
    "CWE-676": ["CWE-121", "CWE-122", "CWE-787"],              # strcpy → overflow family
    "CWE-14": [],                                                # not in Juliet
    "CWE-78":  ["CWE-78"],
}
```

When validating a finding emitted as CWE-X against expected CWE-Y, mark
CWE-match if `CWE-Y in CWE_ALIAS_MAP[CWE-X]`. This fixes the "0% strict
recall" we saw — most findings are semantically right but tagged with
parent CWE.

**Acceptance criteria:** strict recall@CWE > recall@any was already
high; should converge to ≥ 60% with proper aliasing.

**Effort:** 0.5 day.

---

### F6.5 — Comprehensive benchmark + per-CWE iteration

After F6.1-F6.4, re-run the Juliet benchmark with bigger samples:

```bash
python scripts/bench_juliet.py \
  --cwes 121,122,124,125,126,127,134,190,191,415,416,476,78 \
  --samples-per-cwe 100 \
  --runners heuristic,semgrep,hybrid \
  --baseline-files 50
```

Then for each CWE that's < 90% recall, do gap analysis:
- Pick 10 false-negative cases
- Identify what pattern they share that we miss
- Add specific rule
- Re-run that CWE's bench, iterate

**Acceptance criteria:**
- ≥ 8 of top-10 CWEs at ≥ 80% recall
- Average recall ≥ 70%
- FPR proxy ≤ 15%

**Effort:** 1-2 days iterative.

---

### F6.6 — Pattern library schema + tooling

Currently patterns live in:
- `priority.py` (regex list)
- `cve_corpus.py` (RAG)
- `semgrep_tool.py` (external rules)
- Hardcoded in `_build_isolation_poc`

Consolidate into `src/kryon/skills/patterns/` with a uniform schema:

```yaml
# patterns/cwe-190.yaml
cwe: CWE-190
name: Integer Overflow
aliases: [CWE-191, CWE-194, CWE-195, CWE-196, CWE-197]
detection:
  - regex: r"\b\w+\s*[\+\*]\s*\w+\s*\)"
    confidence: low
    context_required:
      - one_of: ["malloc", "alloca", "memcpy"]
        within_lines: 5
  - semgrep_rule: kryon.cwe-190.arith-in-alloc
verification:
  poc_skeleton: |
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
    int main() {
        size_t n = (size_t)-1;
        size_t total = n * 2;  // overflow
        char *p = malloc(total);
        if (p) p[0] = 0;
        return 0;
    }
  asan_class: undefined-behavior
escalation_hints:
  - "If overflow flows into alloc size, the allocation is undersized → OOB writes"
fpr_filters:
  - skip_if: "size_t" in declaration  # safer
  - skip_if: surrounding `if` checks bounds
```

`patterns/loader.py` reads all YAMLs, exposes:
- `get_pattern(cwe)` → dict
- `iter_detection_patterns(cwe)` → list of `(regex, semgrep_id)` tuples
- `get_poc_template(cwe)` → str
- `get_asan_class(cwe)` → str

`HeuristicHunter`, `SemgrepHunter`, validator all consume this single
source of truth. New CWE coverage = add a YAML, no Python edits.

**Effort:** 0.5-1 day refactor.

---

## 3. Dependencies + execution order

```
F6.6 pattern schema      ──┐ (refactor first so subsequent
                           │  patterns slot in cleanly)
                           │
                           ├─→ F6.1 custom semgrep rules
                           │   (highest impact, ~10 CWE files)
                           │
                           ├─→ F6.2 heuristic patterns
                           │   (CWE-190, CWE-476, etc.)
                           │
                           └─→ F6.3 FPR reduction
                               (cuts noise to acceptable levels)

F6.4 CWE label normalization   (independent, ~0.5 day)

F6.5 comprehensive benchmark + iterate  (continuous, until target)
```

**Total effort estimate:** 4-7 days active work. Iteration F6.5 can
continue indefinitely as we discover new gaps.

---

## 4. Acceptance criteria for F6 as a whole

- [ ] At least 10 CWEs have curated YAML patterns under
      `src/kryon/skills/patterns/`
- [ ] Custom Kryon semgrep rules under
      `src/kryon/skills/patterns/semgrep/` total ≥ 30 rules
- [ ] Heuristic FPR on zlib baseline ≤ 20%
- [ ] Hybrid recall@any-finding on Juliet top-10 CWEs ≥ 80% average
- [ ] Hybrid recall@CWE-match (with aliases) on top-10 CWEs ≥ 60% average
- [ ] FPR proxy on zlib baseline ≤ 15% across all runners
- [ ] `docs/BENCHMARKS.md` includes per-CWE table, updated each commit

If we hit average ≥ 80% recall + ≤ 15% FPR, **Kryon enters commercial
SAST tier** (Coverity-comparable on the metrics that matter).

---

## 5. Where 100% breaks down — limitations to document honestly

Not every Juliet test is statically detectable without flow analysis:

- **CWE-401** memory leak via missing free — needs path analysis
- **CWE-369** divide by zero on attacker-controlled denominator — needs
  range tracking
- **CWE-606** unchecked input for loop condition — needs taint propagation
- Multi-file flow variants (a.c → b.c → c.c through function returns)
  — single-file scanners can't see across translation units

These will be left as **F7 work** (proper data-flow + interprocedural
analysis, requires building or integrating a real engine like
CodeQL/Joern). For F6, we cap our ambition at within-function +
within-file analysis, which covers ~80-90% of Juliet patterns.

---

## 6. Open questions

1. **Use semgrep Pro free tier?** semgrep.dev offers a free tier with
   more rules — but requires login + sends metadata to their cloud.
   Conflicts with our "all local" stance. Recommendation: stay OSS.
2. **Build our own AST patterns with tree-sitter?** Adds a heavy dep
   but unlocks much better C/C++ analysis. Recommendation: defer until
   F6.5 iteration shows we've hit a regex ceiling.
3. **Run benchmark in CI?** Adds ~5-10 min per push but catches recall
   regressions immediately. Recommendation: yes, gate via `--samples-per-cwe 5`
   for CI, full run nightly.

---

## 7. Concrete first-week sprint

Day 1: F6.6 pattern schema refactor (consolidate)
Day 2: F6.1 custom semgrep rules (top-5 CWEs first)
Day 3: F6.2 heuristic pattern expansion (CWE-190, 476, 415, 78)
Day 4: F6.3 FPR reduction filters
Day 5: F6.4 CWE label normalization + F6.5 first re-run
Day 6: Per-CWE iteration on lowest performers
Day 7: Full benchmark + write up new BENCHMARKS.md

End-of-week target: **≥ 70% average recall on top-10 CWEs**.

If we hit it, we're shipping a benchmark-defensible product. If we
don't, the per-CWE breakdown tells us exactly where to invest more.

---

## 8. Risk + mitigations

| Risk | Mitigation |
|---|---|
| Custom rules increase FPR on real code | Benchmark FPR on zlib at every change; revert if > 20% |
| Tree-sitter integration creep | Stay regex+semgrep until measurable need |
| Some Juliet templates need DFA we don't have | Document as F7, don't pretend we cover them |
| Patterns over-fit to Juliet | Cross-validate on one external repo (libxml2, sqlite) |

Ready to start. Recommendation: F6.6 (schema) first so subsequent work
slots cleanly. ¿Confirmás y arrancamos?
