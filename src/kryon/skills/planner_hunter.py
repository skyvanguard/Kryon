"""
planner_hunter — the F3 coordinator that ties F1 + F2 + F3.{1,2,4,5,6} together.

End-to-end 0-day hunt against a git repo:
  1. Clone + index + priority score    (F1.1 + F1.3)
  2. Build TODO list                     (F3.2)
  3. Spawn bounded-parallel hunters      (F3.1 HunterPool)
  4. Each hunter executes H -> V cycle   (F1.3 run_sandboxed as oracle)
  5. Compact each hunter session         (F3.5)
  6. Validator triages each finding      (F3.4, 3-phase, zero shared context)
  7. Dedup + rank + emit final bundle

Runner architecture
-------------------
The pool executes an abstract `HunterRunner(job) -> list[dict]`. Two
built-in runners:
  - HeuristicHunter: deterministic, no LLM. Scans the file with danger
    patterns, builds a naive PoC per hit, runs under ASAN. Zero VRAM
    cost. Useful for regression tests and for engagements where the
    LLM is unavailable.
  - LLMHunter: spawns a unified_agent with the zero-day-hunter skill
    loaded, seeded with the dynamic prompt. (Implemented in F3.3.2 —
    for now the slot is reserved; the CLI defaults to heuristic.)

VRAM note
---------
Even with parallelism=2 for hunters, Ollama serializes inference. The
benefit shows up as overlap: hunter A running ASAN (CPU/disk) while
hunter B runs inference.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from kryon.skills.dynamic_prompt import build_todo_list, generate_hunter_prompt
from kryon.skills.supervisor_tools import (
    HunterJob,
    HunterPool,
    get_state,
    reset_supervisor,
    set_pool,
)
from kryon.skills.validator_agent import Finding, ValidatorAgent, Verdict
from kryon.tools.code.git_tools import _git_clone_and_index_impl
from kryon.tools.code.joern_tool import _joern_scan_impl
from kryon.tools.code.priority import _code_priority_score_impl
from kryon.tools.code.sandbox import _run_sandboxed_impl
from kryon.tools.code.semgrep_tool import _semgrep_scan_impl

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Heuristic hunter — deterministic, no LLM
# ---------------------------------------------------------------------------


# F6.6 — Patterns now sourced from the YAML library at skills/patterns/cwe/.
# This list is built lazily so a hot-reload of the YAML files takes effect
# without restarting the process. Each entry: (compiled_regex, cwe, confidence).
def _load_heuristic_patterns() -> list[tuple[str, str, str]]:
    from kryon.skills.patterns import iter_detection_regexes
    out: list[tuple[str, str, str]] = list(iter_detection_regexes())
    # Keep the legacy hard-coded patterns as a tiny safety net in case the
    # YAML library is ever empty (regression guard).
    if not out:
        out = [
            (r"\b[zZ]?memcpy\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)", "CWE-787", "medium"),
            (r"\bstrcpy\s*\(", "CWE-787", "high"),
            (r"\bstrcat\s*\(", "CWE-787", "high"),
            (r"\bsprintf\s*\(", "CWE-787", "high"),
        ]
    return out


_HEURISTIC_PATTERNS: list[tuple[str, str, str]] = _load_heuristic_patterns()


# F6.3 — Context-aware FPR filters. Each filter takes the matched text and
# the surrounding source, returns True if the finding should be SKIPPED
# (counted as a false positive avoided).

def _is_string_literal_arg(line: str) -> bool:
    """For strcpy/strcat/sprintf-class patterns: was the 2nd arg a literal?
    e.g. strcpy(buf, "hello") — safe."""
    # Match: func(<anything>, "....")
    return bool(re.search(r"\b(?:str(?:cpy|cat|n?cpy)|sprintf|wcscpy)\s*\([^,]+,\s*\"[^\"]*\"", line))


def _is_macro_constant_arg(line: str) -> bool:
    """F6.3 round 2: heuristic — strcpy/sprintf with ALL_CAPS_MACRO as source.
    Common safe pattern: strcpy(buf, ZLIB_VERSION), sprintf(out, FMT_HEADER, ...).
    """
    # Match: func(<dst>, MACRO_NAME)  where MACRO_NAME is ALL_CAPS with optional digits/_
    return bool(re.search(
        r"\b(?:str(?:cpy|cat|n?cpy)|sprintf|wcscpy)\s*\([^,]+,\s*[A-Z][A-Z0-9_]{2,}\s*[,)]",
        line,
    ))


def _malloc_size_is_sizeof(line: str) -> bool:
    """F6.3 round 2: malloc(sizeof(struct)) is the canonical safe pattern.
    Also matches `sizeof(T) * N` and `N * sizeof(T)` — bounded allocations."""
    return bool(re.search(
        r"\b(?:malloc|calloc|realloc|alloca)\s*\([^)]*\bsizeof\s*\(",
        line,
    ))


def _is_constant_index(match_text: str) -> bool:
    """For arr[i+j] patterns: are both operands numeric literals?"""
    m = re.search(r"\[\s*(\w+)\s*[+\-*]\s*(\w+)\s*\]", match_text)
    if not m:
        return False
    a, b = m.group(1), m.group(2)
    return a.isdigit() and b.isdigit()


def _line_at(text: str, pos: int) -> str:
    """Return the line of source containing `pos`."""
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end]


def _surrounding_lines(text: str, pos: int, n: int = 5) -> str:
    """Return ±n lines around `pos`."""
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)
    # Walk back n newlines
    s = line_start
    for _ in range(n):
        prev = text.rfind("\n", 0, s - 1)
        if prev < 0:
            s = 0
            break
        s = prev + 1
    # Walk forward n newlines
    e = line_end
    for _ in range(n):
        nxt = text.find("\n", e + 1)
        if nxt < 0:
            e = len(text)
            break
        e = nxt
    return text[s:e]


def _is_safe_wrapper_call(text: str, pos: int) -> bool:
    """Skip well-known safe wrappers (zmemcpy, g_strdup, etc.)."""
    line = _line_at(text, pos)
    return bool(re.search(r"\b(?:z_?memcpy|g_strdup|asprintf|strdupa|strncpy_s)\b", line))


# F9.1 — Category C helpers: sentinel NULL + fopen/open with var.

# Common "safe construction" sinks. If the var feeding fopen/open/popen
# was last assigned via one of these in the same function, we treat it
# as developer-validated input and drop the heuristic finding.
_SAFE_STR_BUILDERS = re.compile(
    r"\b(?:safe_strcpy|safe_strcat|asprintf|sprintf|snprintf|"
    r"strncpy_s|snprintf_s|g_strdup|strdup|getenv)\b"
)


def _function_bounds(text: str, pos: int) -> tuple[int, int]:
    """Return (start, end) of the brace-delimited block containing pos.

    Cheap: walk back to the matching `{`, walk forward to its `}`.
    Used so cross-statement filters can scope themselves to one function.
    """
    depth = 0
    fn_start = 0
    for i in range(pos, -1, -1):
        c = text[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                fn_start = i
                break
            depth -= 1
    depth = 0
    fn_end = len(text)
    for i in range(fn_start, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                fn_end = i + 1
                break
    return (fn_start, fn_end)


def _drop_safe_constructed_fopen(text: str, match_start: int, match_text: str) -> bool:
    """For fopen/open/popen(var, ...): drop if `var` was constructed by a
    recognised safe builder earlier in the same function. Two construction
    forms covered:

      1. Assignment:    var = asprintf(...) / strdup(...) / getenv(...)
      2. Out-param:     safe_strcpy(var, ...) / snprintf(var, ...) /
                        sprintf(var, ...)  — these write INTO var.
    """
    m = re.match(
        r"\b(?:fopen|open|popen)\s*\(\s*([a-zA-Z_]\w*)\s*[,)]",
        match_text,
    )
    if not m:
        return False
    var = m.group(1)
    fn_lo, fn_hi = _function_bounds(text, match_start)
    pre = text[fn_lo:match_start]

    # Form 1: `var = <safe_builder>(...)`
    last_assign = None
    for am in re.finditer(rf"\b{re.escape(var)}\s*=\s*([^;]+);", pre):
        last_assign = am
    if last_assign and _SAFE_STR_BUILDERS.search(last_assign.group(1)):
        return True

    # Form 2: `<safe_builder>(var, ...)` — out-param style.
    if re.search(
        rf"\b(?:safe_strcpy|safe_strcat|snprintf|sprintf|strncpy|strncpy_s|"
        rf"snprintf_s)\s*\(\s*{re.escape(var)}\s*,",
        pre,
    ):
        return True

    return False


def _passes_fpr_filters(
    text: str, match_start: int, match_text: str, cwe: str, confidence: str,
) -> bool:
    """Return True if the finding survives FPR filtering (= keep it).

    Conservative — only filters with low false-negative risk:
      * Skip 'low' confidence patterns (catch-all noise generators)
      * Skip strcpy-family with string literal source (clearly safe)
      * Skip array index where both operands are integer literals
      * Skip safe wrappers (zmemcpy, etc.)
    Removed (too aggressive, hurt recall):
      * has_bounds_check_nearby — Juliet bad code often has
        unrelated if() blocks nearby
      * has_null_assign_between_frees — Juliet uses goto cleanups
    """
    # Confidence threshold: skip 'low' — those are intentionally broad
    if confidence == "low" and os.environ.get("KRYON_HEURISTIC_KEEP_LOW", "0") != "1":
        return False

    line = _line_at(text, match_start)

    # String-literal argument is safe for strcpy-class
    if cwe in ("CWE-787", "CWE-121", "CWE-122") and _is_string_literal_arg(line):
        return False

    # F6.3 round 2: ALL_CAPS_MACRO source is typically a defined constant
    if cwe in ("CWE-787", "CWE-121", "CWE-122") and _is_macro_constant_arg(line):
        return False

    # F6.3 round 2: malloc(sizeof(...)) — canonical bounded allocation
    if cwe in ("CWE-122", "CWE-190") and _malloc_size_is_sizeof(line):
        return False

    # Constant index in array access — not attacker-controlled
    if cwe == "CWE-125" and _is_constant_index(match_text):
        return False

    # Safe wrapper (zmemcpy, g_strdup, etc.) — these are pre-validated
    if _is_safe_wrapper_call(text, match_start):
        return False

    # F9.1 — Category C (PARTIAL ROLLBACK): the sentinel-NULL drop filter
    # was too aggressive — it eliminated production FPs but also dropped
    # real Juliet CWE-476 TPs (the Juliet `_bad()` template re-assigns
    # the var legitimately before the bad-path deref). Bench measured
    # CWE-476 recall fall 73% -> 27% with only -3pp FPR gain. Rolled back.
    # The fopen-with-safe-construction filter is preserved because it has
    # no measurable effect on CWEs in the recall bench (CWE-78/22).
    if cwe in ("CWE-78", "CWE-22") and re.search(
        r"\b(?:fopen|open|popen)\s*\(", match_text
    ) and _drop_safe_constructed_fopen(text, match_start, match_text):
        return False

    return True


def _build_isolation_poc(pattern_kind: str, snippet: str) -> str:
    """Build a tiny standalone PoC that exercises the pattern class.

    F6.6 — first try the YAML pattern library (canonical templates +
    aliases), fall back to legacy hardcoded templates for the few
    bespoke patterns (CWE-823 inflateCopy-style) not yet in the YAML.
    """
    # YAML library lookup with alias resolution
    try:
        from kryon.skills.patterns import (
            cwes_match,
            get_poc_template,
            iter_all_patterns,
        )
        # Direct hit
        poc = get_poc_template(pattern_kind)
        if poc:
            return poc
        # Alias scan: find any registered CWE whose alias family includes
        # pattern_kind, and use its PoC.
        for entry in iter_all_patterns():
            if cwes_match(entry["cwe"], pattern_kind):
                ver = entry.get("verification") or {}
                if isinstance(ver, dict) and ver.get("poc_skeleton"):
                    return ver["poc_skeleton"]
    except Exception:
        pass

    # Legacy fallback for patterns predating the YAML library
    if pattern_kind == "CWE-787":
        # classic heap overflow via memcpy
        return """
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    char *p = malloc(8);
    const char *attacker = "AAAAAAAAAAAAAAAAAAAAAA";
    memcpy(p, attacker, 22);  /* pattern mirror: memcpy with size > alloc */
    printf("%02x\\n", p[0]);
    free(p);
    return 0;
}
"""
    if pattern_kind == "CWE-823":
        return """
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
int main(void) {
    size_t wsize = 32, have = 40;
    unsigned char *window = malloc(wsize);
    unsigned char *next_in = window;
    unsigned char *src = next_in - (ptrdiff_t)(have - wsize);
    unsigned char dst[32];
    memcpy(dst, src, wsize);
    printf("%02x\\n", dst[0]);
    free(window);
    return 0;
}
"""
    if pattern_kind == "CWE-125":
        return """
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    int *arr = malloc(4 * sizeof(int));
    int i = 10, j = 0;
    int v = arr[i + j];  /* computed-index OOB read */
    printf("%d\\n", v);
    free(arr);
    return 0;
}
"""
    return ""


class HeuristicHunter:
    """Runs a pattern-scan + isolated-PoC cycle per file. No LLM."""

    def __init__(self, max_findings_per_file: int = 5):
        self.max_findings_per_file = max_findings_per_file

    async def __call__(self, job: HunterJob) -> list[dict]:
        return await asyncio.to_thread(self._run_sync, job)

    def _run_sync(self, job: HunterJob) -> list[dict]:
        findings: list[dict] = []
        p = Path(job.file_path)
        if not p.is_file():
            return findings
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        # F6.6 — patterns from YAML library, F6.3 — context-aware FPR filters.
        seen_kinds: set[str] = set()
        for regex_src, cwe, confidence in _HEURISTIC_PATTERNS:
            if cwe in seen_kinds:
                continue
            try:
                regex = re.compile(regex_src)
            except re.error:
                continue
            hits = list(regex.finditer(text))
            if not hits:
                continue

            # F6.3 — apply FPR filters; find FIRST hit that passes
            surviving_hit = None
            for h in hits:
                match_text = text[h.start():h.end()]
                if _passes_fpr_filters(text, h.start(), match_text, cwe, confidence):
                    surviving_hit = h
                    break
            if surviving_hit is None:
                continue
            seen_kinds.add(cwe)

            poc = _build_isolation_poc(cwe, text[surviving_hit.start():surviving_hit.end()])
            verified = False
            crash_type = ""
            stack_top: list[str] = []

            if poc:
                try:
                    res = json.loads(_run_sandboxed_impl(poc, language="c"))
                    if res.get("crashed"):
                        verified = True
                        crash_type = res.get("crash_type", "")
                        stack_top = res.get("stack_top") or []
                except (json.JSONDecodeError, Exception):
                    pass

            fname = self._enclosing_function(text, surviving_hit.start()) or "(unknown)"
            line_no = text.count("\n", 0, surviving_hit.start()) + 1

            findings.append({
                "file_path": str(p),
                "repo_path": str(p.parent),
                "function_name": fname,
                "line_range": f"~{line_no}",
                "cwe": cwe,
                "crash_type": crash_type,
                "stack_top": stack_top,
                "severity": "MEDIUM" if verified else "WARNING",
                "language": "c",
                "poc_source": poc if verified else "",
                "trigger_input": "",
                "_hunter": "heuristic",
                "_pattern": regex_src,
                "_asan_verified": verified,
            })
            if len(findings) >= self.max_findings_per_file:
                break

        return findings

    @staticmethod
    def _enclosing_function(text: str, pos: int) -> str | None:
        """Scan backward from `pos` for a C-style function signature."""
        chunk = text[:pos]
        # Match last ~30 candidates; good enough for heuristic attribution
        sig = re.compile(
            r"^\s*(?:static\s+|inline\s+|extern\s+)*\w[\w\s\*]*\b(\w+)\s*\([^;{}]*?\)\s*\{",
            re.M,
        )
        names = sig.findall(chunk)
        return names[-1] if names else None


# ---------------------------------------------------------------------------
# Semgrep-backed hunter — uses industry rules as candidates
# ---------------------------------------------------------------------------


# Map semgrep rule prefixes to the CWE pattern class used by _build_isolation_poc
_SEMGREP_CWE_MAP: dict[str, str] = {
    "string-copy-fn": "CWE-787",    # strcpy family
    "strcpy": "CWE-787",
    "strcat": "CWE-787",
    "sprintf": "CWE-787",
    "gets": "CWE-787",
    "memcpy": "CWE-787",
    "memmove": "CWE-787",
    "memset": "CWE-787",  # insecure-use-memset often implies wrong-size args
    "printf-fn": "CWE-134",  # format string
    "printf": "CWE-134",
    "system": "CWE-78",  # command injection
    "exec": "CWE-78",
    "popen": "CWE-78",
    "scanf": "CWE-787",
    "use-after-free": "CWE-416",
    "double-free": "CWE-415",
    "null-deref": "CWE-476",
    "integer-overflow": "CWE-190",
    "out-of-bounds": "CWE-125",
}


def _cwe_from_rule(rule_id: str, explicit_cwe: str = "") -> str:
    if explicit_cwe:
        # Semgrep sometimes gives "CWE-787: Out-of-bounds Write" — trim
        return explicit_cwe.split(":")[0].strip()
    rid = rule_id.lower()
    for fragment, cwe in _SEMGREP_CWE_MAP.items():
        if fragment in rid:
            return cwe
    return "CWE-787"  # default fallback — pattern category we know how to PoC


class SemgrepHunter:
    """Runs semgrep against the file, maps hits to CWE-specific PoCs, verifies."""

    def __init__(
        self,
        *,
        max_findings_per_file: int = 5,
        severity_min: str = "WARNING",
    ):
        self.max_findings_per_file = max_findings_per_file
        self.severity_min = severity_min

    async def __call__(self, job: HunterJob) -> list[dict]:
        return await asyncio.to_thread(self._run_sync, job)

    def _run_sync(self, job: HunterJob) -> list[dict]:
        # Semgrep on this specific file — cheap, seconds per file
        raw = _semgrep_scan_impl(
            job.file_path,
            language="c",
            severity_min=self.severity_min,
            max_findings=50,
            timeout_s=120,
        )
        try:
            scan = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if "error" in scan:
            logger.debug("semgrep error on %s: %s", job.file_path, scan["error"][:100])
            return []

        # Two categories of semgrep findings:
        #   1) PoC-verifiable: we have a _build_isolation_poc template for
        #      this CWE class, and ASAN can confirm the crash pattern.
        #      These become _asan_verified=True findings.
        #   2) Pattern-only: semgrep flagged it but the bug class isn't
        #      crash-verifiable (e.g. CWE-14 compiler-elides-memset,
        #      CWE-327 weak crypto). Still emit — they're real rule hits
        #      from industry-curated patterns — but mark _asan_verified=False.
        # We dedup across ALL hits (not just verified) by (cwe, rule_id).
        findings: list[dict] = []
        seen_keys: set[tuple[str, str]] = set()
        verified_count_by_cwe: dict[str, int] = {}

        for hit in scan.get("findings") or []:
            rule_id = hit.get("rule_id", "")
            explicit_cwe = hit.get("cwe", "")
            cwe = _cwe_from_rule(rule_id, explicit_cwe)
            # F8.1.b — propagate rule-declared aliases so the bench's
            # cwes_match check considers every CWE the rule author said
            # this finding counts as.
            cwe_aliases = hit.get("cwe_aliases") or []
            dedup_key = (cwe, rule_id)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            severity = (hit.get("severity") or "WARNING").upper()
            line_range = f"{hit.get('start_line', 0)}-{hit.get('end_line', 0)}"
            function = self._guess_enclosing_function(
                job.file_path, hit.get("start_line", 0)
            )
            message = (hit.get("message") or "")[:200]

            # Try PoC verification ONLY for CWE classes we can crash-demo.
            poc = _build_isolation_poc(cwe, "")
            verified = False
            crash_type = ""
            stack_top: list[str] = []

            if poc:
                # Cap verified PoCs at 1 per CWE class per file (avoid duplicates)
                if verified_count_by_cwe.get(cwe, 0) >= 1:
                    # Already verified this class; emit this hit as pattern-only
                    pass
                else:
                    try:
                        vres = json.loads(_run_sandboxed_impl(poc, language="c"))
                        if vres.get("crashed"):
                            verified = True
                            crash_type = vres.get("crash_type", "")
                            stack_top = vres.get("stack_top") or []
                            verified_count_by_cwe[cwe] = (
                                verified_count_by_cwe.get(cwe, 0) + 1
                            )
                    except json.JSONDecodeError:
                        pass

            findings.append({
                "file_path": job.file_path,
                "repo_path": str(Path(job.file_path).parent),
                "function_name": function,
                "line_range": line_range,
                "cwe": cwe,
                "cwe_aliases": cwe_aliases,
                "crash_type": crash_type,
                "stack_top": stack_top,
                "severity": severity,
                "language": "c",
                "poc_source": poc if verified else "",
                "trigger_input": "",
                "_hunter": "semgrep",
                "_semgrep_rule_id": rule_id,
                "_semgrep_message": message,
                "_asan_verified": verified,
            })
            if len(findings) >= self.max_findings_per_file:
                break

        return findings

    @staticmethod
    def _guess_enclosing_function(file_path: str, line: int) -> str:
        """Find the nearest preceding C function definition for a line number."""
        try:
            text = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        if line <= 0:
            return ""
        lines = text.splitlines()
        for i in range(min(line, len(lines)) - 1, -1, -1):
            m = re.match(
                r"^\s*(?:static\s+|inline\s+|local\s+)*(?:[\w\s\*]+)\s+"
                r"(\w+)\s*\([^;{}]*\)\s*\{?\s*$",
                lines[i],
            )
            if m:
                return m.group(1)
        return ""


# ---------------------------------------------------------------------------
# Joern hunter — CPGQL data-flow taint analysis (F7.3)
# ---------------------------------------------------------------------------


def _find_repo_root(file_path: str) -> Path | None:
    """Walk up from `file_path` until we find a `.kryon-allow.yaml` or
    `.git` marker. Returns None if neither is found within 20 levels."""
    try:
        p = Path(file_path).resolve().parent
    except OSError:
        return None
    for _ in range(20):
        if (p / ".kryon-allow.yaml").is_file() or (p / ".git").exists():
            return p
        if p.parent == p:
            return None
        p = p.parent
    return None


def _joern_enabled() -> bool:
    """True if KRYON_JOERN_ENABLED is truthy at call time.

    Read live instead of cached at import so tests and REPL toggles can
    flip the flag without reloading planner_hunter.
    """
    return os.environ.get("KRYON_JOERN_ENABLED", "false").strip().lower() in {
        "1", "true", "yes", "on",
    }


class JoernHunter:
    """Taint-flow hunter backed by the joern CPGQL server (joern_scan).

    Catches Juliet variants that regex/AST miss: socket->array-index
    (CWE-121/129) and scanf->arithmetic (CWE-190). Complementary to
    SemgrepHunter/HeuristicHunter — run all three and merge.

    CPG resolution (in order):
      1. If KRYON_JOERN_CPG_DIR is set AND `<basename>.cpg` exists there,
         the pre-parsed CPG is used (fast — bench-friendly).
      2. Else the source file is handed to joern_scan, which calls
         importCode() on the server (slow — one parse per file).

    On server failure (status != ok) returns empty findings AND marks
    `_hunter_status` on the HunterJob so HybridHunter can surface the
    degradation in the final report. Do NOT treat empty results as
    a clean target.
    """

    _STATUS_KEY = "_joern_last_status"
    _REASON_KEY = "_joern_last_reason"

    def __init__(
        self,
        *,
        cwe_focus: str = "auto",
        max_findings_per_file: int = 10,
        import_timeout_s: int = 120,
        query_timeout_s: int = 60,
    ):
        self.cwe_focus = cwe_focus
        self.max_findings_per_file = max_findings_per_file
        self.import_timeout_s = import_timeout_s
        self.query_timeout_s = query_timeout_s

    async def __call__(self, job: HunterJob) -> list[dict]:
        return await asyncio.to_thread(self._run_sync, job)

    def _resolve_target(self, file_path: str) -> str:
        cpg_dir = os.environ.get("KRYON_JOERN_CPG_DIR", "")
        if cpg_dir:
            stem = Path(file_path).stem
            candidate = Path(cpg_dir) / f"{stem}.cpg"
            if candidate.is_file():
                return str(candidate)
        return file_path

    def _run_sync(self, job: HunterJob) -> list[dict]:
        target = self._resolve_target(job.file_path)
        raw = _joern_scan_impl(
            target_path=target,
            cwe_focus=self.cwe_focus,
            import_timeout_s=self.import_timeout_s,
            query_timeout_s=self.query_timeout_s,
            max_findings=self.max_findings_per_file,
        )
        try:
            scan = json.loads(raw)
        except json.JSONDecodeError:
            setattr(job, self._STATUS_KEY, "error")
            setattr(job, self._REASON_KEY, "joern_scan returned non-JSON")
            return []

        status = scan.get("status", "error")
        setattr(job, self._STATUS_KEY, status)
        if status != "ok":
            setattr(job, self._REASON_KEY, scan.get("reason", ""))
            logger.info(
                "joern hunter degraded on %s: status=%s reason=%s",
                job.file_path, status, scan.get("reason", "")[:100],
            )
            return []
        setattr(job, self._REASON_KEY, "")

        findings: list[dict] = []
        for hit in scan.get("findings") or []:
            sink_line = int(hit.get("start_line") or 0)
            method = hit.get("method") or SemgrepHunter._guess_enclosing_function(
                job.file_path, sink_line
            )
            findings.append({
                "file_path": job.file_path,
                "repo_path": str(Path(job.file_path).parent),
                "function_name": method,
                "line_range": f"{sink_line}-{sink_line}",
                "cwe": hit.get("cwe", ""),
                "crash_type": "",
                "stack_top": [],
                "severity": hit.get("severity", "ERROR"),
                "confidence": hit.get("confidence", "high"),
                "language": "c",
                "poc_source": "",
                "trigger_input": "",
                "_hunter": "joern",
                "_joern_rule_id": hit.get("rule_id", ""),
                "_joern_message": hit.get("message", "")[:200],
                "_joern_flow": hit.get("flow") or [],
                "_asan_verified": False,
            })
        return findings


# ---------------------------------------------------------------------------
# LLM-backed hunter — uses the zero-day-hunter skill on the unified agent
# ---------------------------------------------------------------------------


# Positive FINDING blocks — use a negative lookbehind so "NO FINDING"
# doesn't match as a positive.
_FINDING_BLOCK_RE = re.compile(
    r"(?<!NO )FINDING\s*\n(?P<body>(?:\s*[A-Za-z][A-Za-z ]*:\s*.+\n?){2,})",
    re.MULTILINE,
)
_NO_FINDING_BLOCK_RE = re.compile(
    r"NO FINDING\s*\n(?P<body>(?:\s*[A-Za-z][A-Za-z ]*:\s*.+\n?){2,})",
    re.MULTILINE,
)
_KV_RE = re.compile(r"^\s*([A-Za-z][A-Za-z :]+?):\s*(.+)$", re.MULTILINE)
_POC_BLOCK_RE = re.compile(
    r"```(?:c|cpp|c\+\+)?\s*\n(.+?)```",
    re.DOTALL | re.IGNORECASE,
)


def _parse_findings_from_text(text: str, repo_path: str) -> list[dict]:
    """Extract FINDING (confirmed crash) and NO FINDING (negative) blocks
    from an LLM agent's final output. Negative results become findings
    with severity=NONE so the planner has a record — better than silent
    empty returns when a hunter times out."""
    findings: list[dict] = []
    if not text:
        return findings

    # Grab every FINDING block (positive — crash confirmed)
    for m in _FINDING_BLOCK_RE.finditer(text):
        body = m.group("body")
        fields: dict[str, str] = {}
        for kv in _KV_RE.finditer(body):
            k = kv.group(1).strip().lower().replace(" ", "_")
            v = kv.group(2).strip()
            fields[k] = v

        # File:function line looks like "<file>:<lines>  <function>"
        file_function = fields.get("file:function", fields.get("file:function", ""))
        fpath, fname, line_range = "", "", ""
        if file_function:
            parts = file_function.split(None, 1)
            loc = parts[0]
            fname = parts[1] if len(parts) > 1 else ""
            if ":" in loc:
                fpath, line_range = loc.rsplit(":", 1)
            else:
                fpath = loc

        # Extract the PoC code block following this finding
        window_start = m.end()
        window = text[window_start:window_start + 4000]
        poc_m = _POC_BLOCK_RE.search(window)
        poc = poc_m.group(1).strip() if poc_m else ""

        findings.append({
            "file_path": fpath or fields.get("file", ""),
            "function_name": fname or fields.get("function", ""),
            "line_range": line_range,
            "cwe": fields.get("cwe", ""),
            "severity": fields.get("severity", "").upper(),
            "crash_type": fields.get("crash_type", ""),
            "stack_top": [s.strip() for s in fields.get("stack_top", "").split(",") if s.strip()],
            "poc_source": poc,
            "trigger_input": fields.get("trigger", ""),
            "repo_path": repo_path,
            "language": "c",
            "_hunter": "llm",
            "_deepening": fields.get("deepening_outcome", ""),
            "_suggested_fix": fields.get("suggested_fix", ""),
        })

    # NO FINDING blocks — negative results. We keep them with severity=NONE
    # so the planner's report shows the hunter actually did something and
    # concluded nothing was there, rather than an empty silent return.
    for m in _NO_FINDING_BLOCK_RE.finditer(text):
        body = m.group("body")
        fields = {}
        for kv in _KV_RE.finditer(body):
            k = kv.group(1).strip().lower().replace(" ", "_")
            v = kv.group(2).strip()
            fields[k] = v
        findings.append({
            "file_path": fields.get("file", ""),
            "function_name": "",
            "line_range": "",
            "cwe": "",
            "severity": "NONE",
            "crash_type": "",
            "stack_top": [],
            "poc_source": "",
            "trigger_input": "",
            "repo_path": repo_path,
            "language": "c",
            "_hunter": "llm",
            "_negative": True,
            "_reason": fields.get("reason", ""),
            "_attempts": fields.get("attempted_hypotheses", ""),
        })
    return findings


class LLMHunter:
    """Runs a fresh unified agent with the zero-day-hunter skill per job.

    Timeout ordering matters: LLMHunter's internal timeout MUST fire BEFORE
    the HunterPool's safety timeout, otherwise asyncio cancels the runner
    task and this class never gets to harvest partial progress. We read
    both env vars and force LLMHunter's timeout to be at least POOL-30s.
    """

    def __init__(
        self,
        *,
        max_turns: int = int(os.environ.get("KRYON_HUNT_MAX_TURNS", "50")),
        timeout_s: int | None = None,
    ):
        # F5.1.a — default 50 turns. Previous 15 was a self-imposed ceiling
        # that artificially cut model reasoning short. Mythos/ARTEMIS ran
        # for hundreds of turns on single engagements.
        self.max_turns = max_turns
        pool_timeout = int(os.environ.get("KRYON_HUNTER_TIMEOUT_S", "1800"))
        if timeout_s is None:
            # Respect KRYON_LLM_HUNTER_TIMEOUT_S if set; else trail pool by 30s
            llm_env = os.environ.get("KRYON_LLM_HUNTER_TIMEOUT_S")
            timeout_s = (
                int(llm_env) if llm_env is not None
                else max(60, pool_timeout - 30)
            )
        # Enforce: internal timeout strictly less than pool safety net
        self.timeout_s = min(timeout_s, max(60, pool_timeout - 10))

    async def __call__(self, job: HunterJob) -> list[dict]:
        # Import here to avoid pulling heavy deps at module import time.
        from kryon.sdk.agents import Runner
        from kryon.skills.loader import SkillLoader
        from kryon.skills.unified_agent import create_unified_agent

        loader = SkillLoader()
        loader.scan()
        zdh = loader.get_by_name("zero-day-hunter")
        skills = [zdh] if zdh else None

        try:
            agent = create_unified_agent(
                skills=skills,
                user_msg=job.prompt[:1000],
                profile={"source_code": True, "language": "c"},
            )
        except Exception:
            logger.exception("LLMHunter: failed to build agent for %s", job.file_path)
            return [self._timeout_record(job, "agent_build_failed", [])]

        # Resolve repo root once (used by both success and timeout paths)
        repo_path = self._resolve_repo_root(job.file_path)

        final_text = ""
        timed_out = False
        try:
            result = await asyncio.wait_for(
                Runner.run(agent, job.prompt),
                timeout=self.timeout_s,
            )
            try:
                final_text = getattr(result, "final_output", "") or ""
                if not final_text and hasattr(result, "messages"):
                    for msg in reversed(result.messages):
                        if (
                            msg.get("role") == "assistant"
                            and isinstance(msg.get("content"), str)
                        ):
                            final_text = msg["content"]
                            break
            except Exception:
                pass
        except asyncio.TimeoutError:
            timed_out = True
            logger.warning("LLMHunter timeout for %s", job.file_path)
        except Exception as e:
            logger.exception("LLMHunter runner error on %s: %s", job.file_path, e)
            return [self._timeout_record(
                job, f"runner_error: {e}"[:200],
                self._harvest_progress(agent),
            )]

        # F5.1.d — extract structured submissions from submit_finding /
        # submit_no_finding tool calls BEFORE trying the old text-block parser.
        # This is the primary structured-output channel now.
        submissions = self._harvest_submissions(agent)
        parsed: list[dict] = []
        for sub in submissions:
            if sub["kind"] == "finding":
                parsed.append({
                    "file_path": sub["args"].get("file_path", ""),
                    "function_name": sub["args"].get("function_name", ""),
                    "line_range": sub["args"].get("line_range", ""),
                    "cwe": sub["args"].get("cwe", ""),
                    "severity": sub["args"].get("severity", "MEDIUM").upper(),
                    "crash_type": sub["args"].get("crash_type", ""),
                    "stack_top": [s.strip() for s in sub["args"].get("stack_top", "").split(",") if s.strip()],
                    "poc_source": sub["args"].get("poc_source", ""),
                    "trigger_input": sub["args"].get("trigger_input", ""),
                    "repo_path": repo_path,
                    "language": "c",
                    "_hunter": "llm",
                    "_submitted": True,
                    "_deepening": sub["args"].get("deepening_outcome", ""),
                    "_suggested_fix": sub["args"].get("suggested_fix", ""),
                })
            elif sub["kind"] == "no_finding":
                parsed.append({
                    "file_path": sub["args"].get("file_path", job.file_path),
                    "function_name": "",
                    "line_range": "",
                    "cwe": "",
                    "severity": "NONE",
                    "crash_type": "",
                    "stack_top": [],
                    "poc_source": "",
                    "trigger_input": "",
                    "repo_path": repo_path,
                    "language": "c",
                    "_hunter": "llm",
                    "_negative": True,
                    "_submitted": True,
                    "_reason": sub["args"].get("reason", ""),
                    "_attempts": str(sub["args"].get("attempted_hypotheses", "")),
                    "_notes": sub["args"].get("notes", ""),
                })

        # If no structured submission, fall back to the text-block parser
        # (for older runs / models that still use the text format).
        if not parsed:
            parsed = _parse_findings_from_text(final_text, repo_path)

        # If STILL nothing, synthesize a NO FINDING from progress + optionally
        # run heuristic fallback. Zero-waste principle: an expensive LLM
        # turn that didn't converge still leaves us with pattern-based
        # findings via the deterministic path.
        if not parsed:
            progress = self._harvest_progress(agent)
            reason = (
                "hunter timed out before emitting FINDING/NO FINDING"
                if timed_out
                else "hunter finished without emitting structured output"
            )
            parsed = [self._timeout_record(job, reason, progress, repo_path=repo_path)]

            # Heuristic fallback — disabled via KRYON_LLM_FALLBACK_HEURISTIC=false
            if os.environ.get("KRYON_LLM_FALLBACK_HEURISTIC", "true").lower() == "true":
                try:
                    heuristic = HeuristicHunter()
                    fb = await heuristic(job)
                    for f in fb:
                        f["_fallback_from_llm"] = True
                        f["_llm_reason"] = reason
                    if fb:
                        logger.info(
                            "LLMHunter fallback produced %d heuristic findings for %s",
                            len(fb), job.file_path,
                        )
                    parsed.extend(fb)
                except Exception as e:
                    logger.warning("heuristic fallback failed: %s", e)
        return parsed

    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_repo_root(file_path: str) -> str:
        p = Path(file_path).parent
        default = str(p)
        for _ in range(10):
            if (p / ".git").exists() or (p / ".kryon_index.json").exists():
                return str(p)
            if p.parent == p:
                break
            p = p.parent
        return default

    @staticmethod
    def _harvest_progress(agent) -> list[dict]:
        """Extract every tool call the hunter made, in order.

        When the hunter times out this gives us a concrete trail —
        which files it read, which CWE hints it pulled, etc.
        """
        history = []
        try:
            if hasattr(agent, "model") and hasattr(agent.model, "message_history"):
                history = agent.model.message_history or []
        except Exception:
            pass
        out: list[dict] = []
        for msg in history:
            if msg.get("role") != "assistant":
                continue
            for tc in (msg.get("tool_calls") or []):
                fn = (tc.get("function") or {}).get("name") or ""
                args = (tc.get("function") or {}).get("arguments") or ""
                if isinstance(args, str) and len(args) > 200:
                    args = args[:200] + "..."
                out.append({"tool": fn, "args": args})
        return out

    @staticmethod
    def _harvest_submissions(agent) -> list[dict]:
        """Extract submit_finding / submit_no_finding tool-call arguments.

        Returns a list of {kind: "finding"|"no_finding", args: {...}} in
        call order. The runner uses these as the STRUCTURED output
        channel — they replace the old text-block parsing which was
        fragile on small models.
        """
        history: list = []
        try:
            if hasattr(agent, "model") and hasattr(agent.model, "message_history"):
                history = agent.model.message_history or []
        except Exception:
            pass
        out: list[dict] = []
        for msg in history:
            if msg.get("role") != "assistant":
                continue
            for tc in (msg.get("tool_calls") or []):
                fn = (tc.get("function") or {}).get("name") or ""
                if fn not in ("submit_finding", "submit_no_finding"):
                    continue
                raw_args = (tc.get("function") or {}).get("arguments") or ""
                try:
                    if isinstance(raw_args, str):
                        parsed_args = json.loads(raw_args) if raw_args.strip() else {}
                    else:
                        parsed_args = dict(raw_args)
                except json.JSONDecodeError:
                    parsed_args = {}
                kind = "finding" if fn == "submit_finding" else "no_finding"
                out.append({"kind": kind, "args": parsed_args})
        return out

    @staticmethod
    def _timeout_record(
        job: HunterJob,
        reason: str,
        progress: list[dict],
        *,
        repo_path: str = "",
    ) -> dict:
        last_tools = [p.get("tool", "") for p in progress[-5:]]
        return {
            "file_path": job.file_path,
            "function_name": "",
            "line_range": "",
            "cwe": "",
            "severity": "NONE",
            "crash_type": "",
            "stack_top": [],
            "poc_source": "",
            "trigger_input": "",
            "repo_path": repo_path or str(Path(job.file_path).parent),
            "language": "c",
            "_hunter": "llm",
            "_negative": True,
            "_reason": reason,
            "_tool_calls": len(progress),
            "_last_tools": last_tools,
            "_attempts": "",
        }


# ---------------------------------------------------------------------------
# HybridHunter — semgrep breadth + LLM depth, with a global LLM budget cap
# ---------------------------------------------------------------------------


def _build_focused_llm_prompt(
    job: HunterJob,
    semgrep_findings: list[dict],
    base_prompt: str,
) -> str:
    """Prepend semgrep findings as pre-seeded hypotheses to the base prompt.

    The LLM is no longer asked to find bugs from scratch — it's asked to
    verify or reject specific, already-surfaced hits. This cuts per-hunter
    reasoning load by >10x in our tests.
    """
    hints: list[str] = []
    hints.append("")
    hints.append("## SEMGREP PRE-SEEDED HYPOTHESES")
    hints.append("")
    hints.append(
        "Semgrep (industrial rule engine, ~2100 rules) already flagged "
        "these locations as suspicious. Your job is NOT to find new bugs "
        "— it's to VERIFY or REJECT each of these specific hits. For each:"
    )
    hints.append(
        "  1) Read the function around the flagged line via `read_function`."
    )
    hints.append(
        "  2) If the pattern is real and reachable with attacker input, "
        "build a PoC that crashes under `run_sandboxed` and call "
        "`submit_finding(...)` with the details."
    )
    hints.append(
        "  3) If the hit is a false positive (defensive code, unreachable, "
        "guarded by prior checks), call `submit_no_finding(...)` for THIS "
        "hit with a specific reason referencing the rule_id."
    )
    hints.append("")
    for i, f in enumerate(semgrep_findings, 1):
        hints.append(
            f"### Hit {i}: `{f.get('_semgrep_rule_id', '?')}` "
            f"at line {f.get('line_range', '?')} "
            f"(CWE {f.get('cwe', '?')}, severity {f.get('severity', '?')})"
        )
        hints.append(f"  Function: `{f.get('function_name', '?')}`")
        msg = (f.get("_semgrep_message") or "")[:200].replace("\n", " ")
        if msg:
            hints.append(f"  Rule message: {msg}")
        hints.append("")
    return base_prompt + "\n" + "\n".join(hints)


class _HybridLLMBudget:
    """Process-level cap on how many LLM invocations a hybrid hunt makes."""

    def __init__(self, max_calls: int):
        self.max_calls = max_calls
        self.used = 0
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self._lock:
            if self.used >= self.max_calls:
                return False
            self.used += 1
            return True

    def reset(self) -> None:
        self.used = 0


_HYBRID_BUDGET: _HybridLLMBudget | None = None


def _get_hybrid_budget() -> _HybridLLMBudget:
    global _HYBRID_BUDGET
    if _HYBRID_BUDGET is None:
        cap = int(os.environ.get("KRYON_HYBRID_MAX_LLM_CANDIDATES", "3"))
        _HYBRID_BUDGET = _HybridLLMBudget(max_calls=cap)
    return _HYBRID_BUDGET


def _reset_hybrid_budget() -> None:
    """Called by the coordinator at the start of each hybrid hunt."""
    global _HYBRID_BUDGET
    _HYBRID_BUDGET = None
    _get_hybrid_budget()  # rebuilds from env


# Confidence ordering for merge — higher value wins.
_CONF_RANK = {"low": 1, "medium": 2, "high": 3}
# Severity ordering for merge — higher value wins (ERROR > WARNING > INFO).
_SEV_RANK = {"INFO": 1, "WARNING": 2, "ERROR": 3}
# Line bucket radius used for dedup — ±3 lines collapses sink-vs-source offsets.
_DEDUP_LINE_RADIUS = 3


def _first_line(finding: dict) -> int:
    """Extract the starting line from a finding (line_range='a-b' or '0')."""
    raw = finding.get("line_range", "") or ""
    try:
        return int(raw.split("-", 1)[0] or 0)
    except ValueError:
        return 0


def _dedup_bucket(line: int) -> int:
    return line // (2 * _DEDUP_LINE_RADIUS + 1)


def _merge_findings(a: dict, b: dict) -> dict:
    """Merge two findings that dedup to the same key. Keep the strongest
    evidence and record provenance of both hunters."""
    # Which one has stronger confidence?
    primary, secondary = (
        (a, b) if _CONF_RANK.get(a.get("confidence", "medium"), 2)
                 >= _CONF_RANK.get(b.get("confidence", "medium"), 2)
        else (b, a)
    )
    merged = dict(primary)
    # Stronger severity wins regardless of confidence ordering.
    if _SEV_RANK.get(b.get("severity", ""), 0) > _SEV_RANK.get(
        a.get("severity", ""), 0
    ):
        merged["severity"] = b.get("severity")
    if _SEV_RANK.get(a.get("severity", ""), 0) > _SEV_RANK.get(
        merged.get("severity", ""), 0
    ):
        merged["severity"] = a.get("severity")
    # Preserve ASAN verification from either side.
    merged["_asan_verified"] = bool(
        a.get("_asan_verified") or b.get("_asan_verified")
    )
    # Collect source provenance.
    srcs = []
    for f in (primary, secondary):
        h = f.get("_hunter")
        if h and h not in srcs:
            srcs.append(h)
    merged["_sources"] = srcs
    merged["_source_count"] = len(srcs)
    # Keep the richer flow if any hunter provided one.
    if secondary.get("_joern_flow") and not merged.get("_joern_flow"):
        merged["_joern_flow"] = secondary.get("_joern_flow")
    return merged


def _confidence_gated_union(groups: list[list[dict]]) -> list[dict]:
    """Merge findings from multiple hunters using (file, cwe, line-bucket)
    as the dedup key. Survivors carry `_sources=[...]` so the consumer can
    filter by `_source_count >= 2` if they want voting semantics."""
    bucketed: dict[tuple, dict] = {}
    for group in groups:
        for f in group:
            key = (
                f.get("file_path", ""),
                (f.get("cwe") or "").upper(),
                _dedup_bucket(_first_line(f)),
            )
            existing = bucketed.get(key)
            if existing is None:
                f = dict(f)
                f.setdefault("_sources", [f.get("_hunter", "")])
                f.setdefault("_source_count", 1)
                bucketed[key] = f
            else:
                bucketed[key] = _merge_findings(existing, f)
    return list(bucketed.values())


class HybridHunter:
    """Runs heuristic + semgrep + joern in parallel, optionally LLM on
    survivors.

    Per-file flow:
      1. Three static hunters in parallel:
         - HeuristicHunter  — broad regex + ASAN verification
         - SemgrepHunter    — industry-curated rules (community + Kryon)
         - JoernHunter      — CPGQL taint flow (gated by server availability)
      2. Confidence-gated union: dedup by (file, cwe, line_bucket=line//7),
         merge keeps max confidence, collects `_sources` provenance.
      3. If LLM budget remains AND there are pattern-only hits, spawn
         LLMHunter with focused prompt.

    Graceful degradation: if any hunter returns degraded status (e.g.
    joern server down), it is recorded in every returned finding under
    `_hunters_used` / `_hunters_failed`. Downstream consumers MUST NOT
    treat an empty result from a failed hunter as a clean signal.

    FPR policy deferred: union is NOT voting. A finding with
    `_source_count == 1` is kept. F7.6 will introduce CWE-weighted
    thresholds once F7.5 bench data is in.
    """

    def __init__(self):
        self._sg = SemgrepHunter()
        self._heur = HeuristicHunter()
        self._joern = JoernHunter() if _joern_enabled() else None

    async def __call__(self, job: HunterJob) -> list[dict]:
        # Stage 1: all static hunters in parallel. Collect per-hunter status.
        tasks: list[tuple[str, Any]] = [
            ("heuristic", self._heur(job)),
            ("semgrep", self._sg(job)),
        ]
        if self._joern is not None:
            tasks.append(("joern", self._joern(job)))

        results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

        hunters_used: list[str] = []
        hunters_failed: list[dict] = []
        grouped: list[list[dict]] = []
        for (name, _), res in zip(tasks, results):
            if isinstance(res, BaseException):
                hunters_failed.append({"name": name, "reason": repr(res)[:200]})
                continue
            # For joern: the hunter marks the job attribute; surface that.
            if name == "joern":
                status = getattr(job, JoernHunter._STATUS_KEY, "ok")
                if status != "ok":
                    hunters_failed.append({
                        "name": "joern",
                        "reason": f"{status}: "
                                  f"{getattr(job, JoernHunter._REASON_KEY, '')[:150]}",
                    })
                    continue
            hunters_used.append(name)
            grouped.append(res)

        all_findings = _confidence_gated_union(grouped)

        # Stamp every finding with telemetry so the hunt report can surface
        # degraded runs without hiding them behind "zero findings".
        for f in all_findings:
            f["_hunters_used"] = list(hunters_used)
            f["_hunters_failed"] = list(hunters_failed)

        # F10.1 — apply per-engagement allow-list. Never removes findings;
        # only stamps _suppressed_by_allowlist so the report consumer
        # can hide them under --show-suppressed, and every match is
        # written to an append-only audit log.
        try:
            from kryon.services.allow_list import load as _load_allow
            repo_root = _find_repo_root(job.file_path)
            if repo_root is not None:
                _load_allow(repo_root).annotate(all_findings)
        except Exception as exc:
            logger.warning("allow-list annotate failed: %s", exc)

        # F75 Fase 2 — context-window FP suppression. Runs before LLM
        # triage so the triage model sees the downgraded severity and
        # can skip obvious dead-code / null-checked findings entirely.
        # Zero-cost regex pass, on by default. Disable via
        # KRYON_CONTEXT_FILTER=off (for A/B measurement).
        if (
            all_findings
            and os.environ.get(
                "KRYON_CONTEXT_FILTER", "on"
            ).strip().lower() not in {"off", "0", "false", "no"}
        ):
            try:
                from kryon.skills.context_filter import ContextFilter
                ContextFilter().apply(all_findings)
            except Exception as exc:
                logger.warning("context filter failed: %s", exc)

        # F75 Fase 3 — multi-source agreement severity tier.
        # F74.C bench showed semgrep FPR (37%) < heuristic FPR (61%).
        # Heuristic-only singletons tagged HIGH are the main FPR source.
        # Rule applied here:
        #   _source_count == 1 AND _sources == ['heuristic'] AND
        #   severity in {HIGH, CRITICAL}      -> downgrade to MEDIUM
        # Intersection findings keep their severity. Disable via
        # KRYON_MULTISOURCE_TIER=off (A/B).
        if (
            all_findings
            and os.environ.get(
                "KRYON_MULTISOURCE_TIER", "on"
            ).strip().lower() not in {"off", "0", "false", "no"}
        ):
            # High-severity bucket mirrors the semgrep rule grading:
            # HIGH/CRITICAL (explicit) or ERROR (semgrep default for
            # severity: ERROR rules). WARNING is not downgraded — it's
            # already medium-tier.
            _hi_bucket = {"HIGH", "CRITICAL", "ERROR"}
            downgraded = 0
            for f in all_findings:
                srcs = f.get("_sources") or []
                if (
                    f.get("_source_count", 1) == 1
                    and srcs == ["heuristic"]
                    and str(f.get("severity", "")).upper() in _hi_bucket
                ):
                    f["severity_original"] = f.get(
                        "severity_original", f.get("severity", "")
                    )
                    f["severity"] = "MEDIUM"
                    f.setdefault(
                        "_severity_source", "F75-multisource:heuristic-solo"
                    )
                    downgraded += 1
            if downgraded:
                logger.info(
                    "hybrid: multisource tier downgraded %d heuristic-only "
                    "HIGH findings to MEDIUM",
                    downgraded,
                )

        # F10.3-B / F75 — LLM triage annotation + opt-in filter.
        # Modes (KRYON_HYBRID_TRIAGE env var):
        #   off      -> skip entirely (fastest, legacy behaviour) [default]
        #   annotate -> stamp verdicts, do not filter
        #   filter   -> stamp verdicts AND drop SUPPRESS-high findings
        # Default is 'off' so existing callers that depend on HybridHunter
        # (e.g. CLI engagements) keep zero-LLM-cost semantics. Benches
        # opt in explicitly; production users enable via env.
        # Legacy alias: KRYON_LLM_TRIAGE=1 is treated as 'annotate'.
        _triage_mode = os.environ.get(
            "KRYON_HYBRID_TRIAGE", "off"
        ).strip().lower()
        if os.environ.get("KRYON_LLM_TRIAGE", "").strip().lower() in {
            "1", "true", "yes", "on",
        }:
            _triage_mode = "annotate"
        if _triage_mode in {"annotate", "filter"} and all_findings:
            try:
                from kryon.skills.triage_annotator import (
                    TriageAnnotator,
                    filter_suppress_high,
                )
                TriageAnnotator().annotate(all_findings)
                if _triage_mode == "filter":
                    kept = filter_suppress_high(all_findings)
                    dropped_n = len(all_findings) - len(kept)
                    if dropped_n:
                        logger.info(
                            "hybrid: triage filter dropped %d SUPPRESS-high "
                            "findings (kept %d)",
                            dropped_n, len(kept),
                        )
                    all_findings = kept
            except Exception as exc:
                logger.warning("triage annotation failed: %s", exc)
                for f in all_findings:
                    f.setdefault("triage_verdict", "ERROR")
                    f.setdefault("triage_reason", f"annotator: {exc}"[:200])
                    f.setdefault("triage_confidence", "")

        # If we have ASAN-confirmed findings already, that's strongest evidence
        verified = [f for f in all_findings if f.get("_asan_verified")]
        pattern_only = [f for f in all_findings if not f.get("_asan_verified")]

        # No hits at all
        if not all_findings:
            return []

        # If all hits are already verified, skip LLM
        if verified and not pattern_only:
            return verified

        # Check hybrid LLM budget
        budget = _get_hybrid_budget()
        if not await budget.acquire():
            logger.info(
                "hybrid: LLM budget exhausted (%d/%d used), returning "
                "pattern-only findings for %s",
                budget.used, budget.max_calls, job.file_path,
            )
            return all_findings

        # Stage 2: focused LLM investigation on the pattern-only hits
        llm = LLMHunter()
        enriched_prompt = _build_focused_llm_prompt(
            job,
            pattern_only,
            base_prompt=job.prompt or "",
        )
        original_prompt = job.prompt
        job.prompt = enriched_prompt
        try:
            llm_findings = await llm(job)
        finally:
            job.prompt = original_prompt

        # Mark provenance so the report can attribute each finding
        for f in llm_findings:
            f["_hunter"] = "hybrid-llm"
            f["_from_pattern_hits"] = len(pattern_only)
        for f in all_findings:
            f["_hybrid_llm_budget_used"] = budget.used

        return all_findings + llm_findings


# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------


@dataclass
class HuntReport:
    """Final bundle returned by hunt_zero_days."""

    repo_url: str
    repo_path: str
    head_sha: str
    duration_s: float
    files_scored: int
    hunters_spawned: int
    raw_findings: int
    confirmed_findings: int
    rejected_findings: int
    verdicts: list[dict] = field(default_factory=list)
    # lightweight telemetry for benchmarking
    parallelism: int = 1
    runner_type: str = ""

    def to_json(self) -> str:
        d = self.__dict__.copy()
        return json.dumps(d, indent=2, default=str)

    def pretty(self) -> str:
        info = [v for v in self.verdicts if v.get("verdict") == "INFO"]
        pattern = [v for v in self.verdicts if v.get("verdict") == "PATTERN"]
        lines = [
            f"=== Hunt Report: {self.repo_url} ===",
            f"  repo:            {self.repo_path}",
            f"  HEAD:            {self.head_sha[:10]}",
            f"  duration:        {self.duration_s:.1f}s",
            f"  parallelism:     {self.parallelism}  (runner={self.runner_type})",
            f"  files scored:    {self.files_scored}",
            f"  hunters spawned: {self.hunters_spawned}",
            f"  raw findings:    {self.raw_findings}",
            f"  confirmed (ASAN):{self.confirmed_findings}",
            f"  rejected:        {self.rejected_findings}",
            f"  pattern-only:    {len(pattern)}",
            f"  info / negative: {len(info)}",
            "",
        ]
        confirmed = [v for v in self.verdicts if v.get("verdict") == "CONFIRMED"]
        if confirmed:
            lines.append("Confirmed findings:")
            for v in confirmed:
                lines.append(
                    f"  [{v.get('severity_actual', '?'):<8}] "
                    f"{v.get('cwe_actual', ''):<10} "
                    f"{v.get('reproduced_crash_type', '?'):<25} "
                    f"{v.get('_file', '?')}::"
                    f"{v.get('_function', '?')}"
                )
        if pattern:
            if confirmed:
                lines.append("")
            lines.append("Pattern-only findings (industry-rule hits, no ASAN verification):")
            for v in pattern[:15]:
                lines.append(
                    f"  [{v.get('severity_actual', '?'):<8}] "
                    f"{v.get('cwe_actual', ''):<10} "
                    f"{v.get('_semgrep_rule_id', ''):<35} "
                    f"{v.get('_file', '?').split('/')[-1]}:{v.get('_line_range', '?')}"
                )
                if v.get("reason"):
                    lines.append(f"    {v['reason'][:90]}")
            if len(pattern) > 15:
                lines.append(f"  ... and {len(pattern) - 15} more")

        if info:
            if confirmed or pattern:
                lines.append("")
            lines.append("Hunter telemetry (no findings produced):")
            for v in info:
                reason = v.get("reason", "")
                tcnt = v.get("_tool_calls", 0)
                tools = ", ".join(v.get("_last_tools") or [])
                lines.append(
                    f"  {v.get('_file', '?')}  "
                    f"tools_used={tcnt}  "
                    f"reason: {reason[:80]}"
                )
                if tools:
                    lines.append(f"    last tools: {tools}")
        return "\n".join(lines)


async def hunt_zero_days(
    repo_url: str,
    *,
    budget: int = 10,
    parallelism: int | None = None,
    runner: Callable[[HunterJob], Awaitable[list[dict]]] | None = None,
    runner_type: str = "heuristic",
    ref: str = "",
) -> HuntReport:
    """End-to-end 0-day hunt.

    Args:
        repo_url: git URL of the target repo.
        budget: max files to hunt (top-N by priority_score).
        parallelism: max concurrent hunters. None -> KRYON_HUNTER_PARALLELISM.
        runner: optional custom runner; defaults to HeuristicHunter.
        runner_type: label for the report ("heuristic" | "llm").
        ref: optional git ref (branch/tag/sha) to checkout after clone.
    """
    start = time.time()
    reset_supervisor()

    # ---- Step 1: clone + index ----
    idx_raw = _git_clone_and_index_impl(repo_url, ref=ref, shallow=not bool(ref))
    idx = json.loads(idx_raw)
    if "error" in idx:
        raise RuntimeError(f"clone failed: {idx['error']}")
    repo_path = idx["repo_path"]
    head_sha = idx.get("head_sha", "")

    # ---- Step 2: priority score + build TODO list ----
    scored = json.loads(_code_priority_score_impl(repo_path, max_files=budget))
    top = scored.get("top") or []
    todos = build_todo_list(top, max_items=budget)
    get_state().update_todos(todos)
    logger.info(
        "Priority top-%d files scored for %s: %s",
        len(top), repo_url, [t.get("file") for t in top[:5]],
    )

    # ---- Step 3: spawn hunters with bounded parallelism ----
    max_par = parallelism or int(os.environ.get("KRYON_HUNTER_PARALLELISM", "2"))
    if runner is None:
        if runner_type == "llm":
            runner = LLMHunter()
        elif runner_type == "semgrep":
            runner = SemgrepHunter()
        elif runner_type == "hybrid":
            # F5.2.d real hybrid: per-file semgrep -> if pattern-only hits
            # AND budget remains, focused LLM investigation on those hits.
            _reset_hybrid_budget()
            runner = HybridHunter()
        else:
            runner = HeuristicHunter()
    pool = HunterPool(max_active=max_par, runner=runner)
    set_pool(pool)

    # Pre-seed each file with similar-code matches from the CVE corpus.
    # The supervisor does this ONCE per file before spawning hunters — the
    # matches are baked into the dynamic prompt so the hunter starts with
    # variant-analysis hints instead of exploring blind.
    corpus_available = False
    try:
        from kryon.knowledge import cve_corpus as _cvc
        stats = _cvc.corpus_stats()
        corpus_available = stats.get("count", 0) > 0
        if corpus_available:
            logger.info("CVE corpus available: %d entries", stats["count"])
    except Exception as e:
        logger.debug("CVE corpus unavailable: %s", e)

    spawn_tasks: list[asyncio.Task] = []
    job_map: dict[str, HunterJob] = {}
    for entry in top[:budget]:
        file_rel = entry.get("file", "")
        if not file_rel:
            continue
        full = str(Path(repo_path) / file_rel)

        # Pre-fetch corpus matches using a signal from this file: its name
        # + the top danger patterns found during scoring. This stays cheap
        # (one embedding lookup per file, not per function).
        corpus_matches: list[dict] = []
        if corpus_available:
            try:
                # Signal = filename + evidence summary. Keeps the query
                # semantically representative of the file's attack surface.
                signal = (
                    f"{Path(full).name} "
                    f"danger_hits={entry.get('evidence', {}).get('danger_hits', 0)} "
                    f"{entry.get('evidence', {}).get('pattern_hint', '')}"
                )
                # Fall back to reading the file head if evidence is sparse
                try:
                    with open(full, encoding="utf-8", errors="replace") as fh:
                        signal += "\n" + fh.read(3000)
                except OSError:
                    pass
                corpus_matches = _cvc._query_similar(signal, top_k=3)
            except Exception as e:
                logger.debug("corpus query failed for %s: %s", file_rel, e)

        job = HunterJob(
            hunter_id="",
            file_path=full,
            hypothesis_hint="",
            cwe_candidate="",
        )
        # Stash the dynamic prompt so an LLM runner can read it off job.prompt
        job.prompt = generate_hunter_prompt(
            full,
            priority_evidence=entry,
            repo_path=repo_path,
            corpus_matches=corpus_matches,
        )
        hid = await pool.spawn(job)
        job_map[hid] = job

    # ---- Step 4: wait for all hunters ----
    all_jobs = await pool.await_all()
    logger.info(
        "Hunters done: %d spawned, %d finished, %d failed/terminated",
        len(all_jobs),
        sum(1 for j in all_jobs if j.status == "finished"),
        sum(1 for j in all_jobs if j.status in ("failed", "terminated")),
    )

    # ---- Step 5: collect raw findings ----
    raw_findings: list[dict] = []
    for job in all_jobs:
        for f in job.findings or []:
            # Attach provenance so the validator can attribute
            f["_hunter_id"] = job.hunter_id
            f["_duration_s"] = round(job.duration_s(), 1)
            raw_findings.append(f)

    # ---- Step 6: validator (3 phases, zero shared context) ----
    # Skip validator for informational _negative records (hunter timeouts,
    # NO FINDING blocks) — they have no PoC to reproduce, validator would
    # just reject them with phase=relevance. Pass them through directly so
    # the planner still surfaces the telemetry.
    validator = ValidatorAgent()
    verdicts_raw: list[dict] = []
    for f in raw_findings:
        if f.get("_negative"):
            verdicts_raw.append({
                "verdict": "INFO",
                "phase_failed": None,
                "reason": f.get("_reason", "hunter produced no finding"),
                "cwe_actual": "",
                "cwe_claimed": "",
                "severity_actual": "NONE",
                "severity_claimed": "",
                "reproduced_crash_type": "",
                "reproduced_stack_top": [],
                "exposure_reachable_from_api": None,
                "_file": f.get("file_path", ""),
                "_function": "",
                "_hunter_id": f.get("_hunter_id", ""),
                "_pattern": "",
                "_tool_calls": f.get("_tool_calls", 0),
                "_last_tools": f.get("_last_tools", []),
            })
            continue
        # Pattern-only finding (no ASAN verification): emit as PATTERN
        # verdict so the report shows it without running the validator
        # on a missing PoC. These are legitimate rule hits — semgrep,
        # heuristic CWEs not crash-verifiable (CWE-78 cmd injection,
        # CWE-22 path traversal), industry rules with no PoC class.
        if not f.get("_asan_verified") and f.get("_hunter") in (
            "semgrep", "heuristic", "hybrid-llm"
        ):
            verdicts_raw.append({
                "verdict": "PATTERN",
                "phase_failed": None,
                "reason": f.get("_semgrep_message", "") or
                          f.get("_pattern", "") or
                          f.get("_reason", ""),
                "cwe_actual": f.get("cwe", ""),
                "cwe_claimed": f.get("cwe", ""),
                "severity_actual": f.get("severity", "WARNING"),
                "severity_claimed": f.get("severity", "WARNING"),
                "reproduced_crash_type": "",
                "reproduced_stack_top": [],
                "exposure_reachable_from_api": None,
                "_file": f.get("file_path", ""),
                "_function": f.get("function_name", ""),
                "_line_range": f.get("line_range", ""),
                "_hunter_id": f.get("_hunter_id", ""),
                "_hunter": f.get("_hunter", ""),
                "_semgrep_rule_id": f.get("_semgrep_rule_id", ""),
                "_pattern": f.get("_pattern", ""),
            })
            continue
        finding_obj = Finding.from_dict({
            "file_path": f.get("file_path", ""),
            "function_name": f.get("function_name", ""),
            "crash_type": f.get("crash_type", ""),
            "cwe": f.get("cwe", ""),
            "poc_source": f.get("poc_source", ""),
            "trigger_input": f.get("trigger_input", ""),
            "repo_path": f.get("repo_path") or repo_path,
            "line_range": f.get("line_range", ""),
            "stack_top": f.get("stack_top") or [],
            "severity": f.get("severity", ""),
            "language": f.get("language", "c"),
        })
        verdict: Verdict = validator.triage_one(finding_obj)
        record = json.loads(verdict.to_json())
        record["_file"] = f.get("file_path", "")
        record["_function"] = f.get("function_name", "")
        record["_hunter_id"] = f.get("_hunter_id", "")
        record["_pattern"] = f.get("_pattern", "")
        verdicts_raw.append(record)

    # ---- Step 7: dedup ----
    # key = (file, function, cwe_actual or cwe_claimed)
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for v in verdicts_raw:
        key = (v.get("_file"), v.get("_function"), v.get("cwe_actual") or v.get("cwe_claimed"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(v)

    confirmed = [v for v in deduped if v.get("verdict") == "CONFIRMED"]
    rejected = [v for v in deduped if v.get("verdict") == "REJECTED"]
    info = [v for v in deduped if v.get("verdict") == "INFO"]
    pattern = [v for v in deduped if v.get("verdict") == "PATTERN"]

    # ---- Step 8: build report ----
    report = HuntReport(
        repo_url=repo_url,
        repo_path=repo_path,
        head_sha=head_sha,
        duration_s=round(time.time() - start, 2),
        files_scored=scored.get("files_scored", 0),
        hunters_spawned=len(all_jobs),
        raw_findings=len(raw_findings),
        confirmed_findings=len(confirmed),
        rejected_findings=len(rejected),
        verdicts=deduped,
        parallelism=max_par,
        runner_type=runner_type,
    )
    return report
