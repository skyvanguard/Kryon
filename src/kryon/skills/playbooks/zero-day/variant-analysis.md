---
name: variant-analysis
description: "Dado un CVE o commit de fix, encuentra call-sites sin parchar — la técnica Mythos de mejor ratio esfuerzo/resultado"
triggers:
  tech: ["c", "cpp", "source_code", "repo"]
  ports: []
  keywords: ["variant", "variante", "similar vulnerability", "same bug elsewhere", "unpatched", "cve analysis", "regression"]
priority: 45
required_tools:
  - git_clone_and_index
  - git_diff_fix
  - read_function
  - find_callers
  - run_sandboxed
  - git_log_security
  - add_to_memory_semantic
---

# Variant Analysis

Per Anthropic's zero-day research: "Claude looked for other places where this function
was called in order to find potentially similar vulnerabilities that were left unpatched."
This is the highest-yield hunting technique — you start with a known-good fix and
find its forgotten siblings.

## When to use

- User gives you a CVE + fix commit, or
- `git_log_security` surfaced a recent security commit, or
- You're auditing a project and want maximum coverage of historical bug patterns.

## Flow

### Step 1 — Ground yourself in the fix

1. `git_diff_fix(repo_path, commit_sha)` — read the before/after.
2. Identify:
   - The **vulnerable function** that was changed.
   - The **check that was added** (bounds test, null check, sanitization).
   - The **input/state that bypasses the old code**.

Do NOT move on until you can articulate in one sentence: *"The old code did X, the new
code does Y, and the bug was triggerable when Z."*

### Step 2 — Enumerate siblings

Pick a target function to analyze. Choose the one most likely to have copies:

- If the fix added a check to a helper (e.g. `check_bounds` inside `parse_frame`), the
  sibling call-sites may live in other parsers.
- If the fix changed a wrapper, all downstream callers need review.

Call `find_callers(repo_path, function_name)` → list of sites.

### Step 3 — Check each site

For each call-site returned:

1. `read_function(file, enclosing_function)` to see the calling context.
2. Ask: **Does this caller perform the equivalent of the new check?**
   - If yes → safe, move on.
   - If no → **candidate variant**. Log: `(file, line, function, reason missing)`.

Be precise: the check might be in the caller of the caller, or be an implicit
pre-condition (input was sanitized upstream). Do NOT flag a variant unless you can
trace the attacker input reaching the vulnerable path without hitting an equivalent
check.

### Step 4 — Validate each candidate via the hunter loop

Hand each candidate variant to the **zero-day-hunter** flow (Phase 3: Verify).
Build a harness calling the candidate call-site with input crafted per the original
trigger, run under `run_sandboxed`.

- Crash → **NEW 0-DAY** (or at least a missed variant of the original CVE). Report
  with explicit reference to the parent CVE.
- No crash → variant looks defended by context; log as negative evidence.

### Step 5 — Report bundle

Emit one report **per confirmed variant**, all referencing the parent fix:

```
VARIANT FINDING
  Parent CVE/fix:    <CVE-YYYY-NNNN or commit_sha>
  Same root cause:   <one-line explanation>
  New location:      <file>:<line>  <function>
  Why missed:        <e.g. "check added in parse_frame but not in parse_header">
  Crash confirmation: <crash_type from run_sandboxed>
  PoC:               <minimal harness>
  Suggested fix:     <apply the same check here>
```

## Anti-patterns

- ❌ Flagging a call-site as "missing the check" without tracing whether an
  upstream frame already performed it.
- ❌ Claiming "same bug" when the root cause is actually different (e.g. the
  fix was for signed overflow, but the candidate you found is an unrelated
  TOCTOU). Be honest about root cause.
- ❌ Skipping Step 4 (verification). Untested "variants" are speculation.

## Example walkthrough

Given fix commit `f7d01aae` in zlib (*"Avoid out-of-bounds pointer arithmetic
in inflateCopy"*):

1. `git_diff_fix` → the patch adds a bounds check before `source->next_in - source->in`.
2. Root cause: pointer subtraction underflow when `next_in < in` (truncated stream).
3. `find_callers(repo, "inflateCopy")` → 0 results in zlib itself (it's a public API).
4. Broaden: `find_callers(repo, "inflate")` for siblings that do similar pointer math.
5. Pick sites; check each for the same pattern `ptr->a - ptr->b` without validation.
6. Harness-verify any candidate under ASAN.

---

The highest-value property of this skill: **every confirmed variant is an instant 0-day**
because the root cause is already publicly known but the fix is incomplete.
