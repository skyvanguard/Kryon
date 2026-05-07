"""LLM narrator for compliance findings — CONTEXT AND REMEDIATION PROSE ONLY.

This module generates the two LLM-authored prose sections that appear in the
compliance PDF (wrapped with the `LLM NARRATIVA` watermark).

Strict boundary: the LLM is given a CheckResult as input and can ONLY output
two string fields (context_prose, remediation_prose). The downstream renderer
verifies these are non-empty strings with no structured content injection.

If LLM is unavailable or returns malformed output, the narrator returns empty
strings — the PDF still ships with just the deterministic sections (safer
fallback than stale/wrong prose).
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass

_DEFAULT_MODEL = os.environ.get("KRYON_COMPLIANCE_NARRATOR_MODEL", "deepseek-chat")
_DEFAULT_ENDPOINT = os.environ.get("OPENAI_BASE_URL", "https://api.deepseek.com/v1")
_DEFAULT_TIMEOUT_S = int(os.environ.get("KRYON_NARRATOR_TIMEOUT_S", "30"))

_PROMPT_TEMPLATE = """You are writing TWO short prose paragraphs for a PCI-DSS v4
compliance audit PDF. Your output appears inside clearly-labeled "LLM NARRATIVA"
blocks; the deterministic verdict and evidence are rendered separately and you
MUST NOT contradict them.

Control: {control_id} — {control_title}
Section: {section}
Verdict: {verdict}
Severity: {severity}
Parsed evidence: {evidence_json}
Static remediation text (authoritative): {remediation_static}

Write two paragraphs in SPANISH, concise (max 3 sentences each):

1. CONTEXT — why this control matters for a banking / cardholder-data
   environment. Do NOT reinterpret the verdict.

2. REMEDIATION_DETAIL — expand on the static remediation text with
   practical operational notes. Do NOT invent alternative commands; expand
   only on what the static text already states.

Reply in EXACTLY this format, nothing else:
CONTEXT: <paragraph>
REMEDIATION_DETAIL: <paragraph>
"""


@dataclass(frozen=True)
class Narrative:
    context_prose: str
    remediation_prose: str


def narrate(check_result_dict: dict, *, timeout_s: int = _DEFAULT_TIMEOUT_S) -> Narrative:
    """Call LLM to produce context + remediation prose for one check.

    Returns empty Narrative on any failure — safer than stale prose.
    """
    prompt = _PROMPT_TEMPLATE.format(
        control_id=check_result_dict.get("control_id", ""),
        control_title=check_result_dict.get("control_title", ""),
        section=check_result_dict.get("section", ""),
        verdict=check_result_dict.get("verdict", ""),
        severity=check_result_dict.get("severity", ""),
        evidence_json=json.dumps(check_result_dict.get("evidence_parsed", {}), ensure_ascii=False)[:1000],
        remediation_static=check_result_dict.get("remediation_static", "")[:800],
    )

    body = json.dumps({
        "model": _DEFAULT_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "top_p": 1,
        "max_tokens": 500,
    }).encode()
    # Pick auth token by endpoint flavour: Ollama accepts any string
    # (including the literal "ollama"); external OpenAI-compat APIs
    # need the real OPENAI_API_KEY.
    _is_ollama = "11434" in _DEFAULT_ENDPOINT or "ollama" in _DEFAULT_ENDPOINT
    _auth_token = "ollama" if _is_ollama else os.environ.get("OPENAI_API_KEY", "")
    req = urllib.request.Request(
        f"{_DEFAULT_ENDPOINT}/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_auth_token}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            doc = json.loads(r.read())
    except Exception:
        return Narrative("", "")

    text = (doc.get("choices") or [{}])[0].get("message", {}).get("content", "")
    ctx_m = re.search(r"CONTEXT:\s*(.+?)(?:\n\s*REMEDIATION_DETAIL:|$)", text, re.S)
    rem_m = re.search(r"REMEDIATION_DETAIL:\s*(.+)", text, re.S)
    ctx = (ctx_m.group(1).strip() if ctx_m else "")[:1200]
    rem = (rem_m.group(1).strip() if rem_m else "")[:1200]
    # Sanitize — strip any accidental HTML the model tried to inject.
    ctx = re.sub(r"<[^>]+>", "", ctx)
    rem = re.sub(r"<[^>]+>", "", rem)
    return Narrative(ctx, rem)


def narrate_all(check_results: list[dict]) -> dict[str, dict]:
    """Run narration for each result. Returns {control_id: {context_prose, remediation_prose}}."""
    out: dict[str, dict] = {}
    for r in check_results:
        n = narrate(r)
        out[r["control_id"]] = {
            "context_prose": n.context_prose,
            "remediation_prose": n.remediation_prose,
        }
    return out
