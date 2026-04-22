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

_DEFAULT_MODEL = os.environ.get("KRYON_TRIAGE_MODEL", "qwen3-coder:30b-32k")
_DEFAULT_ENDPOINT = os.environ.get("OPENAI_BASE_URL", "http://ollama:11434/v1")
_DEFAULT_API_KEY = os.environ.get("OPENAI_API_KEY", "ollama")
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

_PROMPT = """You are a security triage analyst. A static scanner flagged the
following potential vulnerability. Decide if it's a REAL bug (KEEP), a clear
false positive (SUPPRESS), or you can't tell from the snippet (UNCERTAIN).

Rule that fired: {rule_id}
CWE: {cwe}
File: {file}
Line: {line}

Code (the marker > is the flagged line):
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


def _snippet(file_path: str, line: int, ctx: int = 3) -> str:
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
        out.append(f"{marker}{i+1:>5}: {lines[i][:120]}")
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
        line_raw = (finding.get("line_range") or "0-0")
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
            snippet=_snippet(file_path, line),
        )

        # F76.1.b — use Ollama NATIVE API (/api/chat) instead of the
        # OpenAI-compat endpoint (/v1/chat/completions). The native API
        # honors `think: false` per-request; the OpenAI-compat shim
        # silently drops that flag and falls back to thinking-ON, which
        # hangs reasoning-enabled models like kryon-14b on a trivial
        # 3-way classification prompt.
        # The rest of the Kryon system (unified agent, F66 experts,
        # validators) still uses the OpenAI-compat endpoint so thinking
        # stays ON for complex pentest/audit tasks.
        # Endpoint derivation: the injected `endpoint` may point at the
        # OpenAI-compat path (e.g. `http://ollama:11434/v1`); strip the
        # trailing `/v1` so we land on the native chat path.
        base = self.endpoint
        if base.endswith("/v1"):
            base = base[:-3]
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "think": False,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": self.max_tokens,
            },
        }).encode()
        req = urllib.request.Request(
            f"{base}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                doc = json.loads(r.read())
        except Exception as exc:
            logger.warning("triage call failed: %s", exc)
            return TriageDecision("ERROR", f"http: {exc}"[:200], "", time.time() - t0)
        elapsed = time.time() - t0

        text = (doc.get("message") or {}).get("content", "")
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
    return [
        f for f in findings
        if not (
            f.get("triage_verdict") == "SUPPRESS"
            and f.get("triage_confidence") == "high"
        )
    ]
