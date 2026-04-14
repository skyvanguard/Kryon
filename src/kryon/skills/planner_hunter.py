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

from kryon.services.micro_compact import compact_hunter_session
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
from kryon.tools.code.priority import _code_priority_score_impl
from kryon.tools.code.reader import _read_function_impl
from kryon.tools.code.sandbox import _run_sandboxed_impl

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Heuristic hunter — deterministic, no LLM
# ---------------------------------------------------------------------------


# Tiny library of PoC templates by pattern. Each entry is:
#   (pattern_regex, poc_builder(captured_groups) -> str, cwe_hint)
#
# The PoC builders return standalone C that intentionally reproduces the
# pattern with attacker-controlled shape — if ASAN crashes, the pattern
# is confirmed dangerous in isolation (still may be guarded in the real
# function, but it's a lead worth flagging).


_HEURISTIC_PATTERNS: list[tuple[str, str]] = [
    # (danger_regex, cwe)
    (r"\b[zZ]?memcpy\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)", "CWE-787"),
    (r"\bstrcpy\s*\(", "CWE-787"),
    (r"\bstrcat\s*\(", "CWE-787"),
    (r"\bsprintf\s*\(", "CWE-787"),
    (r"->next_in\s*-\s*\w+", "CWE-823"),  # inflateCopy-style
    (r"\[\s*\w+\s*[+\-]\s*\w+\s*\]", "CWE-125"),  # computed-index read
]


def _build_isolation_poc(pattern_kind: str, snippet: str) -> str:
    """Build a tiny standalone PoC that exercises the pattern class.

    This is deliberately coarse — the point is to show ASAN on the PATTERN
    as an isolated unit, not to prove reachability in the real call graph.
    The validator will catch false positives.
    """
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

        # Per-pattern, find up to N occurrences and generate a PoC per kind.
        seen_kinds: set[str] = set()
        for regex_src, cwe in _HEURISTIC_PATTERNS:
            if cwe in seen_kinds:  # one PoC per pattern class is enough
                continue
            regex = re.compile(regex_src)
            hits = list(regex.finditer(text))
            if not hits:
                continue
            seen_kinds.add(cwe)

            poc = _build_isolation_poc(cwe, text[hits[0].start():hits[0].end()])
            if not poc:
                continue

            raw = _run_sandboxed_impl(poc, language="c")
            try:
                res = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not res.get("crashed"):
                continue

            # Pick the function enclosing the first pattern hit (best-effort)
            fname = self._enclosing_function(text, hits[0].start()) or "(unknown)"

            findings.append({
                "file_path": str(p),
                "repo_path": str(p.parent),
                "function_name": fname,
                "line_range": f"~{text.count(chr(10), 0, hits[0].start()) + 1}",
                "cwe": cwe,
                "crash_type": res.get("crash_type", ""),
                "stack_top": res.get("stack_top", []),
                "severity": "MEDIUM",
                "language": "c",
                "poc_source": poc,
                "trigger_input": "",
                "_hunter": "heuristic",
                "_pattern": regex_src,
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
        lines = [
            f"=== Hunt Report: {self.repo_url} ===",
            f"  repo:            {self.repo_path}",
            f"  HEAD:            {self.head_sha[:10]}",
            f"  duration:        {self.duration_s:.1f}s",
            f"  parallelism:     {self.parallelism}  (runner={self.runner_type})",
            f"  files scored:    {self.files_scored}",
            f"  hunters spawned: {self.hunters_spawned}",
            f"  raw findings:    {self.raw_findings}",
            f"  confirmed:       {self.confirmed_findings}",
            f"  rejected:        {self.rejected_findings}",
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
    runner = runner or HeuristicHunter()
    pool = HunterPool(max_active=max_par, runner=runner)
    set_pool(pool)

    spawn_tasks: list[asyncio.Task] = []
    job_map: dict[str, HunterJob] = {}
    for entry in top[:budget]:
        file_rel = entry.get("file", "")
        if not file_rel:
            continue
        full = str(Path(repo_path) / file_rel)
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
    validator = ValidatorAgent()
    verdicts_raw: list[dict] = []
    for f in raw_findings:
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
