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

from kryon.util.severity import severity_rank

# Exploit/finding validators (tools/validation). A call to one of these in the
# tool chain is what promotes a finding from ALLEGED to VERIFIED.
_VALIDATION_TOOLS = (
    "validate_sqli",
    "validate_xss",
    "validate_rce",
    "validate_auth_bypass",
    "validate_finding",
    "validate_detection",
    # D — web exploitation tools emit the same validation_status JSON, so a
    # confirmed upload/deser surfaces in the "Verificado por exploit" section.
    "exploit_file_upload",
    "exploit_java_deserialization",
)

_REPORT_DIR = Path.home() / ".kryon" / "investigate"

# Authoritative verdict emitted by the exploit validators (_build_result):
# `{"validation_status": "confirmed|false_positive|potential", ...}`.
_VERDICT_RE = re.compile(r'"validation_status"\s*:\s*"(confirmed|false_positive|potential)"')

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


_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_BLANK_RUN_RE = re.compile(r"\n{3,}")


def _clean_agent_output(output: str) -> str:
    """Strip reasoning noise from the agent's final prose before it lands in
    the ALEGADO section. Conservative — only removes explicit ``<think>``
    chain-of-thought blocks, collapses long blank runs, and drops
    consecutive duplicate lines (the model repeating itself). Never rewrites
    substantive content."""
    if not output:
        return ""
    text = _THINK_BLOCK_RE.sub("", output)
    text = _BLANK_RUN_RE.sub("\n\n", text)
    out_lines: list[str] = []
    prev = None
    for ln in text.split("\n"):
        s = ln.strip()
        if s and s == prev:
            continue  # drop immediate repeat of the same line
        out_lines.append(ln)
        if s:
            prev = s
    return "\n".join(out_lines).strip()


def _dedup_findings(findings: list[Any]) -> list[Any]:
    """Drop duplicate deterministic findings (same CWE + host + message head).
    Detectors run per-URL, so the same issue can surface more than once."""
    seen: set[tuple[str, str, str]] = set()
    out: list[Any] = []
    for f in findings:
        sig = (
            str(getattr(f, "cwe", "") or ""),
            str(getattr(f, "host", "") or ""),
            (getattr(f, "message", "") or "")[:80],
        )
        if sig in seen:
            continue
        seen.add(sig)
        out.append(f)
    return out


def _rank_findings(findings: list[Any]) -> list[Any]:
    """Order findings by severity (CRITICAL → HIGH → MEDIUM → LOW → INFO →
    unknown), so a critical never reads buried below low-severity noise. Uses
    the canonical severity_rank; stable sort preserves detection order within
    a severity tier."""
    return sorted(findings, key=lambda f: severity_rank(str(getattr(f, "severity", "") or "")))


def _is_needs_review(f: Any) -> bool:
    """F210 — a deterministic finding is NOT ground truth when it carries
    ``needs_verification`` or an inferred/heuristic ``verification_level``
    (banner-spoofable version, version→CVE backport-prone, exposed-appliance
    patch-level unconfirmed, or a check that couldn't complete). Both signals
    are checked so the split is robust regardless of whether the confidence
    scorer already ran. Missing fields → confirmed (backward compatible)."""
    if bool(getattr(f, "needs_verification", False)):
        return True
    return str(getattr(f, "verification_level", "confirmed") or "confirmed").lower() in {"heuristic", "inferred"}


def _finding_line(f: Any, *, with_level: bool = False) -> str:
    cwe = getattr(f, "cwe", "?")
    sev = getattr(f, "severity", "?")
    host = getattr(f, "host", "?")
    msg = (getattr(f, "message", "") or "")[:160]
    # A "judge-confirmed" finding was promoted from `inferred` by the finding-judge
    # (a model), NOT re-probed by a deterministic validator. Tag it so it is never
    # read as proven ground truth even though it sits in the "Verificado" section.
    _lvl = str(getattr(f, "verification_level", "") or "").lower()
    tag = "  ⚖ _adjudicado por modelo (sin re-probe)_" if _lvl == "judge-confirmed" else ""
    if with_level:
        level = str(getattr(f, "verification_level", "heuristic") or "heuristic")
        return f"- **{cwe}** ({sev}, _nivel: {level}_) @ {host}: {msg}{tag}"
    return f"- **{cwe}** ({sev}) @ {host}: {msg}{tag}"


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
    deterministic_findings = _rank_findings(_dedup_findings(deterministic_findings))
    # F210 — split ground-truth (confirmed) from inferred/heuristic so the
    # "Verificado" section only carries what a detector actually probed. The
    # inferred ones (version→CVE, banner fingerprint, exposed-appliance patch
    # level) get their own "requiere verificación" section — not presented as
    # proven. When nothing is flagged (default), the split is a no-op.
    confirmed = [f for f in deterministic_findings if not _is_needs_review(f)]
    needs_review = [f for f in deterministic_findings if _is_needs_review(f)]
    output = _clean_agent_output(output)
    lines: list[str] = [
        "# Investigate report",
        "",
        f"**Prompt**: {prompt}",
        f"**Mode**: {'active' if active else 'passive'} · "
        f"**Tool calls**: {len(chain)} · **Validations run**: {len(validations)}",
        "",
        "## ✅ Verificado (detectores deterministas)",
    ]
    if confirmed:
        lines.extend(_finding_line(f) for f in confirmed)
    else:
        lines.append("- _(ninguno — los detectores deterministas no confirmaron findings)_")
    lines.append("")

    # Demonstrated attack paths — the XBOW signature output. Built from the
    # CONFIRMED findings only (each edge is a validated link), so a chain here is
    # a proven path to impact, not a hypothesis. Multi-step chains are the
    # low+low→critical the individual findings don't show. Placed with the
    # verified section (it derives only from confirmed evidence).
    try:
        from kryon.intelligence.attack_path import build_attack_graph, format_attack_paths

        _paths_md = format_attack_paths(build_attack_graph(None, deterministic_findings))
    except Exception:  # noqa: BLE001 — the report must never fail on the graph
        _paths_md = ""
    if _paths_md:
        lines.append("## 🔗 Attack paths demostrados (cada eslabón validado)")
        lines.append(
            "_Cadenas probadas hacia impacto (RCE / DB / cuenta / admin). Cada arista "
            "proviene de un finding CONFIRMADO — no son hipótesis. Las multi-paso son el "
            "low+low→critical que los findings sueltos no muestran._"
        )
        lines.append(_paths_md)
        lines.append("")

    if needs_review:
        lines.append("## ⚠️ Requiere verificación (detectores inferidos/heurísticos)")
        lines.append(
            "_Señales inferidas (versión/banner spoofeable, mapeo versión→CVE sujeto a "
            "backports, o appliance expuesto con parche sin confirmar). NO son ground "
            "truth — confirmar cada una antes de reportarla._"
        )
        lines.extend(_finding_line(f, with_level=True) for f in needs_review)
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
