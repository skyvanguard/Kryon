"""
Triage annotator (F10.3-B) — LLM-based verdict stamping for scanner findings.

This module adds a `triage_verdict` / `triage_reason` / `triage_confidence`
field to each finding. It does NOT filter. The analyst sees every finding
the pattern hunters produced, optionally sorted by verdict so the LLM's
prioritisation influences review order but never hides signal.

Why annotation instead of filtering:
- F10.3 spike showed qwen3-coder discriminates (SUPPRESS precision 75%
  on spike, TP-preservation imperfect at 80%). A filter would kill TPs.
  Annotation preserves them and lets the analyst decide.
- Makes the claim auditable. Every decision has a verdict + reason; the
  final report can surface the verdict list as a separate lens.

Gate (measured per-bench, not per-call):
- SUPPRESS verdicts must hit precision >= 65% (predicted FP is actually FP).
- KEEP verdicts must hit precision >= 50% (predicted TP is actually TP).
- Below gate -> the annotator is noise, ship nothing.

Concurrency: Ollama serves one request at a time per model. We run calls
serially across findings. Sprint benchmarks have shown qwen3-coder p95
around 5s per triage call.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = os.environ.get("KRYON_TRIAGE_MODEL", "deepseek-chat")
_DEFAULT_ENDPOINT = os.environ.get("OPENAI_BASE_URL", "https://api.deepseek.com/v1")
_DEFAULT_API_KEY = os.environ.get("OPENAI_API_KEY", "")
_DEFAULT_TIMEOUT_S = int(os.environ.get("KRYON_TRIAGE_TIMEOUT_S", "30"))
_DEFAULT_MAX_TOKENS = int(os.environ.get("KRYON_TRIAGE_MAX_TOKENS", "2000"))

# Verdict rank for ship-order sorting. Lower value = higher priority
# (shown to analyst first). KEEP-high first, SUPPRESS-high last.
_VERDICT_PRIORITY = {
    ("KEEP", "high"): 0,
    ("KEEP", "medium"): 1,
    ("KEEP", "low"): 2,
    ("UNCERTAIN", "high"): 3,
    ("UNCERTAIN", "medium"): 3,
    ("UNCERTAIN", "low"): 3,
    ("ERROR", ""): 3,
    ("", ""): 3,  # unannotated
    ("SUPPRESS", "low"): 4,
    ("SUPPRESS", "medium"): 5,
    ("SUPPRESS", "high"): 6,
}

_PROMPT = """You are a security triage analyst reviewing static scanner findings.
Decide: REAL bug (KEEP) | clear false positive (SUPPRESS) | unsure (UNCERTAIN).

BIAS RULES (F76.2/F76.3 — prevent aggressive over-suppression):
1. If the snippet shows a dangerous API (strcpy/strcat/sprintf/memcpy/alloca/
   memmove/realloc/gets) whose size is NOT a compile-time constant, default
   to KEEP.
2. For CWE-121/122 buffer overflows: the unsafe write may be several lines
   AFTER the flagged line. If you only see the allocation/input read, that
   alone is enough signal — KEEP with confidence medium (not SUPPRESS high).
3. For CWE-122 heap overflows specifically: malloc/calloc/realloc followed
   by memmove/memcpy/strcpy is a classic heap-overflow pattern. Always
   KEEP unless the destination size is proven literal via sizeof() or a
   compile-time constant.
4. For CWE-476 null-deref: if the snippet reads a value that could be NULL
   and later dereferences it WITHOUT an intervening null check visible in
   the window, KEEP. Only SUPPRESS when a clear `if (!p) return` appears
   BEFORE the deref.
5. **NEVER judge code based on its filename, path, or structural hints
   about being a test case.** Treat the code as if it were production.
   Do NOT SUPPRESS because:
   - the filename contains "CWE", "bad", "good", "vuln", "test"
   - comments mention "bad sink", "good sink", "vulnerable", "POC"
   - the function is named `main`, `bad()`, `good*()`, `sink()`
   These are common in Juliet/NIST/SARD datasets and in legitimately
   vulnerable production code. Judge the code flow, not the labels.
6. SUPPRESS is reserved for clearly safe patterns in the CODE:
   - size is a compile-time literal or sizeof()
   - the flagged call is inside `#if 0` / `#ifdef DEBUG_ONLY` dead code
   - a valid `if (!p) return` guard is visible in window before the deref
   - the dangerous destination was proven sized equal to source
7. When in doubt → UNCERTAIN (never SUPPRESS just because the snippet
   seems 'ok in isolation').

--- FEW-SHOT EXAMPLES ---

Example 1 (CWE-121 KEEP — heuristic-only signal):
  Rule: heuristic-strcpy  CWE: CWE-121  Line: 45
  >   45: strcpy(local_buf, user_input);
  Output:
    VERDICT: KEEP
    REASON: strcpy with non-literal source can overflow local_buf.
    CONFIDENCE: high

Example 2 (CWE-121 KEEP — allocation only, overflow later):
  Rule: heuristic-alloca  CWE: CWE-121  Line: 32
  >   32: char *buf = (char *)ALLOCA(size);
  Output:
    VERDICT: KEEP
    REASON: ALLOCA with variable size commonly precedes strcpy/memcpy
      overflow further down the function.
    CONFIDENCE: medium

Example 2b (CWE-122 KEEP — heap alloc + memmove, ignore filename):
  File: /somewhere/CWE122_Heap_Based_Buffer_Overflow__memmove_bad.c
  Rule: heuristic-memmove  CWE: CWE-122  Line: 48
      46: data = (char *)malloc(100 * sizeof(char));
  >   48: memmove(data, source, strlen(source));
  Output:
    VERDICT: KEEP
    REASON: memmove copies strlen(source) bytes into a 100-byte heap
      buffer without bound check; heap overflow possible. Do not
      SUPPRESS based on filename/path hints about "test case".
    CONFIDENCE: high

Example 3 (CWE-476 KEEP — deref may happen on a path not shown):
  Rule: semgrep-null-deref  CWE: CWE-476  Line: 78
  >   78: int x = foo->id;
  Output:
    VERDICT: KEEP
    REASON: foo is dereferenced without a visible null check in window.
    CONFIDENCE: medium

Example 4 (CWE-476 SUPPRESS — explicit guard 2 lines above):
  Rule: semgrep-null-deref  CWE: CWE-476
      76: if (!foo) return -1;
  >   78: int x = foo->id;
  Output:
    VERDICT: SUPPRESS
    REASON: foo is explicitly null-checked before the deref.
    CONFIDENCE: high

Example 5 (CWE-190 SUPPRESS — literal size):
  Rule: semgrep-int-overflow  CWE: CWE-190  Line: 12
  >   12: memcpy(dst, src, 32);
  Output:
    VERDICT: SUPPRESS
    REASON: size is a compile-time literal (32), not attacker-controlled.
    CONFIDENCE: high

--- THIS FINDING ---

Rule that fired: {rule_id}
CWE: {cwe}
File: {file}
Line: {line}
Scanner severity: {severity}
Sources: {sources}

Code (the marker > is the flagged line; ±8 line window):
{snippet}

Reply in EXACTLY this format, nothing else:
VERDICT: KEEP | SUPPRESS | UNCERTAIN
REASON: <one short sentence>
CONFIDENCE: high | medium | low
"""


@dataclass
class TriageDecision:
    verdict: str  # "KEEP" | "SUPPRESS" | "UNCERTAIN" | "ERROR"
    reason: str
    confidence: str  # "high" | "medium" | "low" | ""
    latency_s: float


def _snippet(file_path: str, line: int, ctx: int = 8) -> str:
    try:
        from pathlib import Path

        lines = Path(file_path).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    if line <= 0 or line > len(lines):
        return ""
    lo = max(0, line - 1 - ctx)
    hi = min(len(lines), line + ctx)
    out = []
    for i in range(lo, hi):
        marker = ">" if i == line - 1 else " "
        out.append(f"{marker}{i + 1:>5}: {lines[i][:120]}")
    return "\n".join(out)


def _parse(text: str) -> tuple[str, str, str]:
    m_v = re.search(r"VERDICT:\s*(KEEP|SUPPRESS|UNCERTAIN)", text, re.I)
    m_r = re.search(r"REASON:\s*(.+)", text)
    m_c = re.search(r"CONFIDENCE:\s*(high|medium|low)", text, re.I)
    verdict = m_v.group(1).upper() if m_v else "ERROR"
    reason = (m_r.group(1).strip()[:200]) if m_r else text[:200]
    confidence = (m_c.group(1).lower()) if m_c else "medium"
    return (verdict, reason, confidence)


class TriageAnnotator:
    """Annotates findings with LLM triage verdicts. Never filters."""

    def __init__(
        self,
        *,
        model: str = _DEFAULT_MODEL,
        endpoint: str = _DEFAULT_ENDPOINT,
        api_key: str = _DEFAULT_API_KEY,
        timeout_s: int = _DEFAULT_TIMEOUT_S,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
    ) -> None:
        self.model = model
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.timeout_s = timeout_s
        self.max_tokens = max_tokens

    def annotate(self, findings: list[dict]) -> list[dict]:
        """Stamp every finding with triage fields. Returns the same list
        (mutated in place AND returned for call-site convenience)."""
        for f in findings:
            d = self._decide(f)
            f["triage_verdict"] = d.verdict
            f["triage_reason"] = d.reason
            f["triage_confidence"] = d.confidence
            f["triage_latency_s"] = round(d.latency_s, 2)
        return findings

    def _decide(self, finding: dict) -> TriageDecision:
        import time

        file_path = finding.get("file_path", "")
        line_raw = finding.get("line_range") or "0-0"
        line_raw = str(line_raw).lstrip("~")
        try:
            line = int(line_raw.split("-", 1)[0])
        except ValueError:
            line = 0

        prompt = _PROMPT.format(
            rule_id=finding.get("_semgrep_rule_id") or finding.get("_pattern") or "",
            cwe=finding.get("cwe", ""),
            file=file_path,
            line=line,
            severity=finding.get("severity", ""),
            sources=",".join(finding.get("_sources") or []) or "unknown",
            snippet=_snippet(file_path, line),
        )

        # Detect endpoint flavour:
        #   - Ollama native (port 11434 / hostname "ollama"): use /api/chat
        #     which honours `think: false` per-request to skip reasoning.
        #     The OpenAI-compat shim drops `think` and hangs reasoning
        #     models on trivial 3-way classification.
        #   - Anything else (DeepSeek API, OpenAI, vLLM, etc): use the
        #     standard /v1/chat/completions with Bearer auth. We pick a
        #     non-thinking model (deepseek-chat default) so reasoning is
        #     already off — no `think` flag needed.
        is_ollama_native = "11434" in self.endpoint or "ollama" in self.endpoint
        t0 = time.time()
        if is_ollama_native:
            base = self.endpoint
            if base.endswith("/v1"):
                base = base[:-3]
            body = json.dumps(
                {
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "think": False,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "num_predict": self.max_tokens,
                    },
                }
            ).encode()
            req = urllib.request.Request(
                f"{base}/api/chat",
                data=body,
                headers={"Content-Type": "application/json"},
            )
        else:
            body = json.dumps(
                {
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens": self.max_tokens,
                    "stream": False,
                }
            ).encode()
            req = urllib.request.Request(
                f"{self.endpoint}/chat/completions",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
            )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                doc = json.loads(r.read())
        except Exception as exc:
            logger.warning("triage call failed: %s", exc)
            return TriageDecision("ERROR", f"http: {exc}"[:200], "", time.time() - t0)
        elapsed = time.time() - t0

        if is_ollama_native:
            text = (doc.get("message") or {}).get("content", "")
        else:
            text = ((doc.get("choices") or [{}])[0].get("message") or {}).get("content", "")
        verdict, reason, confidence = _parse(text)
        return TriageDecision(verdict, reason, confidence, elapsed)


def triage_sort_key(finding: dict) -> int:
    """Sort key that surfaces KEEP-high first, SUPPRESS-high last."""
    v = finding.get("triage_verdict", "")
    c = finding.get("triage_confidence", "") if v in {"KEEP", "SUPPRESS"} else ""
    return _VERDICT_PRIORITY.get((v, c), 3)


def filter_suppress_high(findings: list[dict]) -> list[dict]:
    """Opt-in filter: drops only SUPPRESS-high verdicts. Keeps SUPPRESS-low
    and SUPPRESS-medium because the LLM was unsure. Triggered by
    `--triage-filter` / `KRYON_TRIAGE_FILTER=true`."""
    return [f for f in findings if not (f.get("triage_verdict") == "SUPPRESS" and f.get("triage_confidence") == "high")]
