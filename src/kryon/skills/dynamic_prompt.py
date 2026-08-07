"""
Dynamic per-sub-agent prompt generator (ARTEMIS technique).

Each hunter spawned by the planner gets a SMALL, focused prompt:
only the single file to attack, the priority evidence that made it
attractive, and optionally a CWE hint or parent CVE. This reduces
per-hunter KV cache size (critical on 12 GB VRAM) and keeps each
hunter's context laser-focused on one target.

Design rules:
  - Prompt body cap: 2000 tokens (~= 8000 chars). Hard-enforced.
  - No generic "you are a security expert" boilerplate — the skill
    playbook (zero-day-hunter.md) already supplies that at agent
    construction time.
  - Cite concrete evidence (danger hits, input signals) so the model
    doesn't have to re-discover why this file is interesting.
  - End with an explicit first action (which tool to call).
"""

from __future__ import annotations

from typing import Any

# Per-prompt limits
_MAX_CHARS = 8000
_MAX_EVIDENCE_LINES = 12


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_hunter_prompt(
    file_path: str,
    priority_evidence: dict[str, Any] | None = None,
    *,
    repo_path: str = "",
    cwe_hint: str = "",
    parent_cve: str = "",
    hypothesis_hint: str = "",
    followups: list[str] | None = None,
    corpus_matches: list[dict] | None = None,
) -> str:
    """Build the prompt body for a single hunter sub-agent.

    Args:
        file_path: Absolute path to the file this hunter owns.
        priority_evidence: One entry from code_priority_score's `top` list
            (has `score`, `loc`, `evidence.{danger_hits, input_hits}`, etc.).
        repo_path: Root of the repo (for find_callers calls).
        cwe_hint: Optional CWE tag to bias the hunter.
        parent_cve: If this came from variant-analysis, the CVE id.
        hypothesis_hint: Optional one-liner suggesting where to look.
        followups: Any queued follow-ups to inject.
    """
    parts: list[str] = []

    # --- Mission line ---
    if parent_cve:
        parts.append(f"VARIANT HUNT. Root CVE: {parent_cve}. Find an unpatched sibling of this bug in the file below.")
    else:
        parts.append("ZERO-DAY HUNT. One file, one H->V->R cycle. Crash under ASAN or the bug does not exist.")

    # --- Target ---
    parts.append("")
    parts.append("## Target")
    parts.append(f"- File: `{file_path}`")
    if repo_path:
        parts.append(f"- Repo root: `{repo_path}`  (use with find_callers, git_diff_fix)")

    # --- Why this file was picked ---
    ev = (priority_evidence or {}).get("evidence") or {}
    score = (priority_evidence or {}).get("score")
    loc = (priority_evidence or {}).get("loc")
    if score is not None or ev:
        parts.append("")
        parts.append("## Priority evidence")
        if score is not None:
            parts.append(f"- Priority score: {score}/5")
        if loc:
            parts.append(f"- Lines of code: {loc}")
        if ev.get("danger_hits") is not None:
            parts.append(
                f"- Dangerous-function hits: {ev['danger_hits']}  "
                "(memcpy/strcpy/sprintf/system/eval/pointer-arith patterns)"
            )
        if ev.get("input_hits") is not None:
            parts.append(f"- Untrusted-input signals: {ev['input_hits']}  (argv/recv/request/BytesIO markers)")

    # --- Steering hints (optional) ---
    if cwe_hint or hypothesis_hint:
        parts.append("")
        parts.append("## Hints")
        if cwe_hint:
            parts.append(f"- Candidate CWE: {cwe_hint}")
        if hypothesis_hint:
            parts.append(f"- Hypothesis seed: {hypothesis_hint}")

    if followups:
        parts.append("")
        parts.append("## Follow-ups from supervisor")
        for f in followups[:5]:
            parts.append(f"- {f}")

    # ARTEMIS-style pre-seeded retrieval: the supervisor ran
    # recall_similar_code_pattern on this file's signal before spawning
    # the hunter. Give the hunter the top CVE matches up-front so it can
    # skip straight to variant-analysis instead of exploring blind.
    if corpus_matches:
        parts.append("")
        parts.append("## Past CVE patches that look similar (pre-fetched from corpus)")
        parts.append(
            "These are patches that fixed similar patterns in other projects."
            " If any match is a twin of code in this file, treat it as a"
            " pre-seeded hypothesis — go verify with run_sandboxed."
        )
        for m in corpus_matches[:3]:
            cve = m.get("cve_id") or m.get("ghsa_id") or "?"
            cwes = m.get("cwe_ids", "") or ""
            repo = m.get("repo", "") or ""
            excerpt = (m.get("pattern_excerpt", "") or "").replace("\n", " ")[:200]
            parts.append(f"- {cve}  [{cwes}]  {repo} — {excerpt}...")

    # --- First action — remove ambiguity about what to call ---
    parts.append("")
    parts.append("## First action")
    parts.append(
        "Call `read_function(file_path, <function_name>)` on the hottest function "
        "in this file. Pick it by scanning for: memcpy/strcpy on attacker-sized "
        "data, pointer arithmetic like `a - b - c`, array indexing with computed "
        "offsets, sprintf without bound, deserialization/exec/system calls. "
        "Do NOT write prose summarizing this prompt — call the tool."
    )

    # --- Closing reminder (matches zero-day-hunter.md Hard rules) ---
    parts.append("")
    parts.append("Remember: no finding without a `run_sandboxed` crash confirmation.")

    body = "\n".join(parts)
    return _clamp(body)


def build_todo_list(
    priority_top: list[dict],
    *,
    max_items: int = 10,
) -> list[dict]:
    """Turn `code_priority_score`'s top files into a TODO list for the supervisor.

    Each TODO is `{file, priority, danger_hits, input_hits, status, hunter_id}`.
    The planner feeds this into `update_supervisor_todo` so the hunt survives
    context compactions.
    """
    todos: list[dict] = []
    for i, entry in enumerate(priority_top[:max_items]):
        ev = entry.get("evidence") or {}
        todos.append(
            {
                "n": i + 1,
                "file": entry.get("file", ""),
                "priority": entry.get("score", 0),
                "danger_hits": ev.get("danger_hits", 0),
                "input_hits": ev.get("input_hits", 0),
                "loc": entry.get("loc", 0),
                "status": "pending",  # pending | running | done | skipped
                "hunter_id": "",  # filled when spawn_hunter returns
            }
        )
    return todos


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _clamp(text: str, limit: int | None = None) -> str:
    # The 8000-char default was calibrated for the 4B-local's tight window; scale
    # it to the model's window so a capable model (V4 1M) gets the full hunter prompt.
    if limit is None:
        from kryon.config.settings import resolve_context_budget

        limit = resolve_context_budget(_MAX_CHARS)
    if len(text) <= limit:
        return text
    return text[: limit - 60] + "\n\n... (prompt truncated to stay within budget)"
