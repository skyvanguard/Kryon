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
    """Runs a fresh unified agent with the zero-day-hunter skill per job."""

    def __init__(
        self,
        *,
        max_turns: int = int(os.environ.get("KRYON_HUNT_MAX_TURNS", "30")),
        timeout_s: int = int(os.environ.get("KRYON_HUNTER_TIMEOUT_S", "900")),
    ):
        self.max_turns = max_turns
        self.timeout_s = timeout_s

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

        parsed = _parse_findings_from_text(final_text, repo_path)

        # If we timed out (or the agent produced no structured output),
        # synthesize a NO FINDING record from whatever progress is visible in
        # the agent's message history. Better than an empty return — the
        # planner gets a row, the operator sees what the hunter saw.
        if not parsed:
            progress = self._harvest_progress(agent)
            reason = (
                "hunter timed out before emitting FINDING/NO FINDING"
                if timed_out
                else "hunter finished without emitting structured output"
            )
            parsed = [self._timeout_record(job, reason, progress, repo_path=repo_path)]
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
        if info:
            if confirmed:
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
                    with open(full, "r", encoding="utf-8", errors="replace") as fh:
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
