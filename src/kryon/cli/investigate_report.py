"""Build + persist a readable `investigate` report (observability + anti-bluff).

Two problems this fixes:
- **Observability**: the agent's result used to go out via a single
  non-flushed ``console.print`` → invisible when piped (non-TTY). Here we build
  a markdown report, persist it to a stable path, and return it for a flushed
  ``print``.
- **Anti-bluff verification**: the report separates **VERIFIED** findings
  (deterministic detectors that ran real tools, plus any ``validate_*`` tool
  that confirmed an exploit) from **ALLEGED** ones (the LLM's prose, which
  needs verification). No claim is presented as proven unless a tool backed it.

Pure/testable: report building takes data in and returns a string; only
``persist_investigate_report`` touches disk.
"""

from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import Any

# Exploit/finding validators (tools/validation). A call to one of these in the
# tool chain is what promotes a finding from ALLEGED to VERIFIED.
_VALIDATION_TOOLS = (
    "validate_sqli",
    "validate_xss",
    "validate_rce",
    "validate_auth_bypass",
    "validate_finding",
    "validate_detection",
)

_REPORT_DIR = Path.home() / ".kryon" / "investigate"

# Authoritative verdict emitted by the exploit validators (_build_result):
# `{"validation_status": "confirmed|false_positive|potential", ...}`.
_VERDICT_RE = re.compile(
    r'"validation_status"\s*:\s*"(confirmed|false_positive|potential)"'
)

# Fallback heuristic for tools that don't emit the structured field. NEGATIONS
# are checked FIRST — mirroring the validators themselves — so "not confirmed",
# "could not be confirmed", "not injectable", etc. are never misread as a
# confirmation (the anti-bluff whole point: nothing shows ✅ unless truly proven).
_NEGATION_MARKERS = (
    "false_positive",
    "false positive",
    "not confirmed",
    "could not be confirmed",
    "unconfirmed",
    "no confirmado",
    "not injectable",
    "not vulnerable",
    "not exploitable",
)
_CONFIRM_MARKERS = ("confirmed", "is vulnerable", "injectable", "exploited")


def _classify_validation(preview: str) -> str:
    """Map a validate_* output to confirmed | false_positive | ran.

    Prefers the validator's own structured ``validation_status`` verdict
    (authoritative); falls back to a negation-first text heuristic only when
    the structured field is absent (e.g. truncated/older outputs)."""
    pl = preview.lower()
    m = _VERDICT_RE.search(pl)
    if m:
        verdict = m.group(1)
        if verdict == "confirmed":
            return "confirmed"
        if verdict == "false_positive":
            return "false_positive"
        return "ran"  # "potential" → no clear verdict
    if any(n in pl for n in _NEGATION_MARKERS):
        return "false_positive"
    if any(c in pl for c in _CONFIRM_MARKERS):
        return "confirmed"
    return "ran"


def _validations_from_chain(chain: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Find validate_* tool calls in the chain and classify their outcome."""
    out: list[dict[str, str]] = []
    for step in chain:
        tool = str(step.get("tool", "") or "")
        if not any(v in tool for v in _VALIDATION_TOOLS):
            continue
        preview = str(step.get("output_preview", "") or "")
        status = _classify_validation(preview)
        out.append({"tool": tool, "status": status, "preview": preview[:160]})
    return out


def build_investigate_report(
    *,
    prompt: str,
    active: bool,
    output: str,
    deterministic_findings: list[Any],
    chain: list[dict[str, Any]],
) -> str:
    """Render a markdown report separating verified vs alleged findings."""
    validations = _validations_from_chain(chain)
    lines: list[str] = [
        "# Investigate report",
        "",
        f"**Prompt**: {prompt}",
        f"**Mode**: {'active' if active else 'passive'} · "
        f"**Tool calls**: {len(chain)} · **Validations run**: {len(validations)}",
        "",
        "## ✅ Verificado (detectores deterministas)",
    ]
    if deterministic_findings:
        for f in deterministic_findings:
            cwe = getattr(f, "cwe", "?")
            sev = getattr(f, "severity", "?")
            host = getattr(f, "host", "?")
            msg = (getattr(f, "message", "") or "")[:160]
            lines.append(f"- **{cwe}** ({sev}) @ {host}: {msg}")
    else:
        lines.append("- _(ninguno — los detectores deterministas no confirmaron findings)_")
    lines.append("")

    if validations:
        lines.append("## 🧪 Verificación por exploit (validate_*)")
        _mark = {
            "confirmed": "✅ CONFIRMADO",
            "false_positive": "❌ FALSO POSITIVO",
            "ran": "▸ ejecutado (sin veredicto claro)",
        }
        for v in validations:
            lines.append(f"- {_mark[v['status']]} — `{v['tool']}`: {v['preview']}")
        lines.append("")

    lines.append("## ⚠️ Análisis del agente (ALEGADO — requiere verificación)")
    lines.append("")
    lines.append(output.strip() or "_(el agente no produjo salida final)_")
    lines.append("")

    if chain:
        lines.append("## 🔗 Cadena de herramientas ejecutada")
        for i, step in enumerate(chain, 1):
            args_preview = str(step.get("args", "") or "")[:120]
            lines.append(f"{i}. `{step.get('tool', '?')}` {args_preview}")
    return "\n".join(lines)


def persist_investigate_report(report_md: str, *, when: str | None = None) -> Path:
    """Write the report to a stable path (~/.kryon/investigate/<ts>.md)."""
    _REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = when or datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = _REPORT_DIR / f"investigate-{ts}.md"
    path.write_text(report_md, encoding="utf-8")
    return path
