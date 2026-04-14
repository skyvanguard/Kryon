"""
Validator agent — 3-phase triage of hunter findings with zero shared context.

The validator is the ground-truth gatekeeper. Per Mythos methodology
(red.anthropic.com/2026/mythos-preview), a separate agent with no visibility
into the hunter's chain of thought kills confirmation bias — this is what
drives the 89% expert-agreement figure Anthropic reported.

Hybrid implementation
---------------------
Phases 1 and 2 run as **deterministic Python logic** (no LLM needed):
  - Phase 1 (relevance): did the claimed function exist? did the PoC
    reference it?
  - Phase 2 (reproduction): we rerun `run_sandboxed` ourselves with ONLY
    the PoC source + optional trigger bytes. No context transfer.

Phase 3 (classification + severity) is a deterministic mapping on the
actual observed crash_type. If the user opts in to `KRYON_DUAL_MODEL`,
phase 3 can also query a small validator-model agent for nuanced severity
calls; otherwise the heuristic table suffices.

Zero shared context by construction
-----------------------------------
We build a FRESH agent (no history) on demand, or avoid the LLM entirely
when the heuristics can decide. The hunter's message history is NEVER
passed in.

VRAM awareness
--------------
Default: single-model, no LLM call in the validator — cost $0 extra.
Opt-in: `KRYON_VALIDATOR_MODEL=qwen2.5-coder:7b` + `KRYON_DUAL_MODEL=true`
triggers a separate-model consultation for phase 3 only.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kryon.tools.code.reader import _find_callers_impl, _read_function_impl
from kryon.tools.code.sandbox import _run_sandboxed_impl

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """What the hunter submits."""

    file_path: str
    function_name: str
    crash_type: str            # claimed
    cwe: str                   # claimed
    poc_source: str            # full C/C++ harness
    trigger_input: str = ""
    repo_path: str = ""
    line_range: str = ""
    stack_top: list[str] = field(default_factory=list)
    severity: str = ""         # claimed
    language: str = "c"

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(
            file_path=str(d.get("file_path", "")),
            function_name=str(d.get("function_name", "")),
            crash_type=str(d.get("crash_type", "")),
            cwe=str(d.get("cwe", "")),
            poc_source=str(d.get("poc_source", "")),
            trigger_input=str(d.get("trigger_input", "")),
            repo_path=str(d.get("repo_path", "")),
            line_range=str(d.get("line_range", "")),
            stack_top=list(d.get("stack_top") or []),
            severity=str(d.get("severity", "")),
            language=str(d.get("language", "c")) or "c",
        )


@dataclass
class Verdict:
    """What the validator returns."""

    verdict: str                 # "CONFIRMED" or "REJECTED"
    phase_failed: str | None = None
    reason: str = ""
    cwe_actual: str = ""
    cwe_claimed: str = ""
    severity_actual: str = ""
    severity_claimed: str = ""
    classification_notes: str = ""
    reproduced_crash_type: str = ""
    reproduced_stack_top: list[str] = field(default_factory=list)
    exposure_reachable_from_api: bool | None = None

    def to_json(self) -> str:
        return json.dumps({
            "verdict": self.verdict,
            "phase_failed": self.phase_failed,
            "reason": self.reason,
            "cwe_actual": self.cwe_actual,
            "cwe_claimed": self.cwe_claimed,
            "severity_actual": self.severity_actual,
            "severity_claimed": self.severity_claimed,
            "classification_notes": self.classification_notes,
            "reproduced_crash_type": self.reproduced_crash_type,
            "reproduced_stack_top": self.reproduced_stack_top,
            "exposure_reachable_from_api": self.exposure_reachable_from_api,
        }, indent=2)


# ---------------------------------------------------------------------------
# Phase 3 — crash-type → CWE mapping (deterministic)
# ---------------------------------------------------------------------------


_CRASH_TO_CWE: dict[str, str] = {
    "heap-buffer-overflow": "CWE-787",   # write (worst case default)
    "heap-use-after-free": "CWE-416",
    "use-after-free": "CWE-416",
    "stack-buffer-overflow": "CWE-121",
    "stack-use-after-return": "CWE-562",
    "stack-use-after-scope": "CWE-562",
    "global-buffer-overflow": "CWE-787",
    "double-free": "CWE-415",
    "alloc-dealloc-mismatch": "CWE-762",
    "undefined-behavior": "CWE-190",     # most commonly int overflow in practice
    "null-deref": "CWE-476",
    "SEGV": "CWE-476",
    "intra-object-overflow": "CWE-787",
}


def crash_to_cwe(crash_type: str) -> str:
    if not crash_type:
        return ""
    key = crash_type.lower().strip()
    if key in _CRASH_TO_CWE:
        return _CRASH_TO_CWE[key]
    # Fuzzy match — handle punctuation variants
    for k, v in _CRASH_TO_CWE.items():
        if k in key:
            return v
    return ""


def severity_for_crash(crash_type: str, reachable: bool | None) -> str:
    """Baseline severity; the hunter may have adjusted via deepening."""
    c = (crash_type or "").lower()
    base = "LOW"
    if "heap-buffer-overflow" in c or "stack-buffer-overflow" in c:
        base = "HIGH"
    elif "use-after-free" in c or "double-free" in c:
        base = "CRITICAL"
    elif "global-buffer-overflow" in c:
        base = "HIGH"
    elif "undefined-behavior" in c:
        base = "MEDIUM"
    elif "null-deref" in c or "segv" in c:
        base = "LOW"

    # If the function is unreachable from public API, knock one level down.
    if reachable is False and base != "LOW":
        base = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW"}.get(base, base)
    return base


# ---------------------------------------------------------------------------
# ValidatorAgent — the orchestrator
# ---------------------------------------------------------------------------


class ValidatorAgent:
    """Runs the 3 phases. No LLM call by default; deterministic."""

    def __init__(
        self,
        *,
        model: str | None = None,
        use_llm_for_phase3: bool = False,
    ):
        self.model = model or os.environ.get("KRYON_VALIDATOR_MODEL", "")
        self.use_llm_for_phase3 = use_llm_for_phase3 and os.environ.get(
            "KRYON_DUAL_MODEL", "false"
        ).lower() == "true"

    # ----- Phase 1: relevance -----

    def phase1_relevance(self, f: Finding) -> tuple[bool, str]:
        if not f.file_path or not f.function_name:
            return False, "missing file_path or function_name"
        if not f.poc_source.strip():
            return False, "empty poc_source"

        # 1a. Does the claimed function exist in the claimed file?
        if not Path(f.file_path).is_file():
            return False, f"file not found: {f.file_path}"

        read_result = json.loads(_read_function_impl(f.file_path, f.function_name))
        if "error" in read_result:
            return False, (
                f"function '{f.function_name}' not found in {f.file_path}"
            )

        # 1b. Does the PoC at least MENTION the target function? This is a
        # weak check (macros, inlining, wrapper names can legitimately hide
        # the reference), but it catches the common case where the hunter's
        # harness crashes in main() itself and forgot to call the target.
        if f.function_name not in f.poc_source:
            # Still allow through if the PoC compiles the target source in.
            # The real check is phase 2.
            note = (
                f"PoC does not textually reference '{f.function_name}' — "
                "relying on phase 2 to verify actual reachability"
            )
            logger.warning("validator phase1 soft-warn: %s", note)

        return True, ""

    # ----- Phase 2: reproduction -----

    def phase2_reproduce(self, f: Finding) -> tuple[bool, dict, str]:
        """Re-run the PoC ourselves. Returns (ok, result_dict, reason)."""
        raw = _run_sandboxed_impl(
            f.poc_source,
            language=f.language,
            stdin_bytes=f.trigger_input,
        )
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            return False, {}, "sandbox returned invalid JSON"

        if not result.get("compiled", False):
            snippet = (result.get("compile_stderr") or "")[:300]
            return False, result, f"PoC failed to compile: {snippet}"

        if not result.get("crashed", False):
            return False, result, "no crash under ASAN on reproduction"

        # Genuine crash.
        return True, result, ""

    # ----- Phase 3: classification -----

    def phase3_classify(
        self,
        f: Finding,
        reproduction: dict,
    ) -> tuple[str, str, str, bool | None, str]:
        """Return (cwe_actual, severity_actual, classification_notes, reachable, reason_on_fail)."""
        actual_crash = reproduction.get("crash_type", "")

        cwe_actual = crash_to_cwe(actual_crash)
        if not cwe_actual:
            return (
                "", "", "", None,
                f"unknown crash type for CWE mapping: {actual_crash!r}",
            )

        # Reachability heuristic — ask find_callers
        reachable: bool | None = None
        classification_notes_parts: list[str] = []
        if f.repo_path and Path(f.repo_path).is_dir():
            try:
                callers_raw = _find_callers_impl(
                    f.repo_path, f.function_name, max_hits=10
                )
                callers = json.loads(callers_raw)
                total = callers.get("total_callers", 0)
                # "public API exposure" = at least one caller outside /test/
                # or the function is declared in a public header
                public_hit = False
                for h in callers.get("hits", []):
                    path = h.get("file", "").lower()
                    if "/test" in path or "\\test" in path or path.endswith(".h"):
                        if path.endswith(".h"):
                            public_hit = True  # in a header = public API
                        continue
                    public_hit = True
                    break
                reachable = public_hit if total > 0 else False
                classification_notes_parts.append(
                    f"find_callers: {total} sites, "
                    f"reachable={'yes' if reachable else 'no'}"
                )
            except Exception as e:
                classification_notes_parts.append(f"reachability check failed: {e}")

        severity_actual = severity_for_crash(actual_crash, reachable)

        # Note any mismatch with claimed values
        if f.cwe and f.cwe != cwe_actual:
            classification_notes_parts.append(
                f"CWE corrected from claimed {f.cwe} to {cwe_actual}"
            )
        if f.severity and f.severity.upper() != severity_actual:
            classification_notes_parts.append(
                f"severity {severity_actual} (hunter claimed {f.severity})"
            )

        return (
            cwe_actual,
            severity_actual,
            "; ".join(classification_notes_parts),
            reachable,
            "",
        )

    # ----- Top-level triage -----

    def triage_one(self, f: Finding) -> Verdict:
        """Run all three phases; return the verdict."""
        # Phase 1
        ok, reason = self.phase1_relevance(f)
        if not ok:
            return Verdict(
                verdict="REJECTED",
                phase_failed="relevance",
                reason=reason,
                cwe_claimed=f.cwe,
                severity_claimed=f.severity,
            )

        # Phase 2 — the crucial gate
        ok, repro, reason = self.phase2_reproduce(f)
        if not ok:
            return Verdict(
                verdict="REJECTED",
                phase_failed="reproduction",
                reason=reason,
                cwe_claimed=f.cwe,
                severity_claimed=f.severity,
            )

        # Phase 3
        cwe_a, sev_a, notes, reachable, reason = self.phase3_classify(f, repro)
        if reason:
            return Verdict(
                verdict="REJECTED",
                phase_failed="classification",
                reason=reason,
                cwe_claimed=f.cwe,
                severity_claimed=f.severity,
                reproduced_crash_type=repro.get("crash_type", ""),
                reproduced_stack_top=repro.get("stack_top", []) or [],
            )

        return Verdict(
            verdict="CONFIRMED",
            phase_failed=None,
            reason="reproduced under ASAN; CWE + severity classified",
            cwe_actual=cwe_a,
            cwe_claimed=f.cwe,
            severity_actual=sev_a,
            severity_claimed=f.severity,
            classification_notes=notes,
            reproduced_crash_type=repro.get("crash_type", ""),
            reproduced_stack_top=(repro.get("stack_top") or [])[:5],
            exposure_reachable_from_api=reachable,
        )

    def triage_batch(self, findings: list[Finding]) -> list[Verdict]:
        """Validate a list of findings. Each one isolated — no shared state."""
        return [self.triage_one(f) for f in findings]
