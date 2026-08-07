"""F186 — Pre-hook output truncation + imperative-prompt builder.

F185.C bench (n=3) showed pre_hooks firing reliably but only 1/3 runs
converted the verbose nuclei/nikto output into structured findings.
The other two got lost in banners, template-load logs, and scan
metadata — by the time the model reached the actual finding lines
the conversation_input was crowded enough that the post-hook
``find SQLi or XSS or RCE`` instruction got drowned out.

F186 takes the raw pre-hook payload and:

1. Detects the tool type via inject_as name or content signature.
2. Parses the tool's known output shape (nuclei severity tags,
   nikto ``+ /path: ...`` lines, generic JSON) and keeps only
   finding-shaped lines.
3. Caps to a top-N count, prioritizing critical/high severities.
4. Strips banners, scan-progress noise, and metadata that doesn't
   help the model emit findings.

Plus ``imperative_findings_suffix`` — a short directive appended
after the evidence block: "Convert each item above into a finding
JSON entry. Do NOT re-invoke these tools."
"""

from __future__ import annotations

import os
import re

# Hard cap on any pre-hook output regardless of tool — keeps the
# context window safe when an unknown tool emits megabytes.
_HARD_LENGTH_CAP = 8000

# Severity ranking for the "keep critical/high first" truncation rule.
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


# nuclei line shape: ``[template-id] [proto] [severity] http://target/...``
_NUCLEI_LINE_RE = re.compile(
    r"^\[(?P<template>[\w\-./]+)\]\s+"
    r"\[(?P<proto>[a-z]+)\]\s+"
    r"\[(?P<severity>critical|high|medium|low|info)\]\s+"
    r"(?P<rest>.+)$",
    re.IGNORECASE,
)


# nikto line shape. Nikto v2.6+ emits findings as
# ``+ [NNNNNN] /path: description.`` where ``[NNNNNN]`` is the
# OSVDB/nikto-internal ID. Older versions sometimes emit
# ``+ /path: description.`` without the bracketed id. The root path
# can appear as ``/`` followed by ``:`` directly (``+ [id] /: ...``)
# so the path body is ``[^:]*`` (zero or more non-colon chars).
# The leading ``+`` plus a slash-rooted token is what distinguishes
# real findings from nikto's metadata lines (``+ Target IP: ...``,
# ``+ Start Time: ...``, ``+ Server: ...``).
_NIKTO_LINE_RE = re.compile(r"^\+\s+(?:\[\d+\]\s+)?/[^:]*:.+$")


# F187 — sqlmap finding markers. Sqlmap emits its verdict in a
# ``sqlmap identified the following injection point(s)`` block and a
# parameter summary like ``Parameter: q (GET)\n  Type: ...``. We
# preserve those plus the "back-end DBMS:" line. Everything else
# (banners, [INFO] testing X, HTTP error stats) goes away.
_SQLMAP_VULNERABLE_RE = re.compile(
    r"is vulnerable|injection point\(s\)|Parameter: |Type: |Title: |Payload: |back-end DBMS:",
    re.IGNORECASE,
)


def _nuclei_severity(line: str) -> int:
    """Return the severity rank for a nuclei finding line. Unknown
    lines sort to the bottom."""
    m = _NUCLEI_LINE_RE.match(line)
    if not m:
        return _SEVERITY_RANK["unknown"]
    return _SEVERITY_RANK.get(m.group("severity").lower(), _SEVERITY_RANK["unknown"])


# F210 — nuclei severity floor. ``info`` templates are overwhelmingly
# tech-detection / TLS-version / header-echo noise: not vulnerabilities,
# but the model converts each line into a confident finding → FP flood.
# We drop anything BELOW the floor before the output ever reaches the
# LLM (noise filtering, not finding suppression — nothing at ``low`` or
# above is touched). Default floor = ``low`` (keep low/medium/high/
# critical, drop info). Operators doing pure recon can lower it with
# ``KRYON_NUCLEI_SEVERITY_FLOOR=info`` to keep everything; raise it to
# ``medium`` for a stricter offensive sweep.
_NUCLEI_FLOOR_DEFAULT = "low"


def _nuclei_floor_rank() -> int:
    raw = os.environ.get("KRYON_NUCLEI_SEVERITY_FLOOR", _NUCLEI_FLOOR_DEFAULT).strip().lower()
    return _SEVERITY_RANK.get(raw, _SEVERITY_RANK[_NUCLEI_FLOOR_DEFAULT])


def _summarize_nuclei(payload: str, *, max_items: int) -> str:
    """Extract nuclei-shaped finding lines, drop those below the
    severity floor, sort by severity, cap to N."""
    floor = _nuclei_floor_rank()
    candidates: list[str] = []
    for raw in payload.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _NUCLEI_LINE_RE.match(line)
        if not m:
            # Banners, [INF] templates loaded, etc. — dropped.
            continue
        if _SEVERITY_RANK.get(m.group("severity").lower(), _SEVERITY_RANK["unknown"]) > floor:
            # Below the floor (e.g. info when floor=low) — noise, dropped.
            continue
        candidates.append(line)

    candidates.sort(key=_nuclei_severity)
    return "\n".join(candidates[:max_items])


def _summarize_nikto(payload: str, *, max_items: int) -> str:
    """Extract nikto ``+ /path: ...`` lines, cap to N. Nikto doesn't
    expose a parseable severity so we preserve order (nikto already
    emits roughly highest-signal first)."""
    candidates: list[str] = []
    for raw in payload.splitlines():
        line = raw.strip()
        if _NIKTO_LINE_RE.match(line):
            candidates.append(line)
    return "\n".join(candidates[:max_items])


def _looks_like_nuclei(inject_as: str, payload: str) -> bool:
    if "nuclei" in inject_as.lower():
        return True
    return bool(_NUCLEI_LINE_RE.search(payload))


def _looks_like_nikto(inject_as: str, payload: str) -> bool:
    if "nikto" in inject_as.lower():
        return True
    return "Nikto v" in payload or _NIKTO_LINE_RE.search(payload) is not None


def _looks_like_sqlmap(inject_as: str, payload: str) -> bool:
    if "sqlmap" in inject_as.lower():
        return True
    return "sqlmap" in payload.lower() or "sqlmap identified" in payload


def _summarize_sqlmap(payload: str, *, max_items: int) -> str:
    """Keep only sqlmap lines that describe a finding (injection
    point, parameter type, payload, backend DBMS). Drop the verbose
    [INFO] testing trail.

    If sqlmap reports no injection ("not appear to be injectable"),
    return a single negative line so the model knows the probe ran.
    """
    candidates: list[str] = []
    not_injectable = False
    for raw in payload.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "not appear to be injectable" in line or "all tested parameters do not appear" in line:
            not_injectable = True
            continue
        if _SQLMAP_VULNERABLE_RE.search(line):
            # Strip the timestamp prefix sqlmap puts on every log line.
            cleaned = re.sub(r"^\[\d{2}:\d{2}:\d{2}\]\s*\[INFO\]\s*", "", line)
            candidates.append(cleaned)

    if not candidates and not_injectable:
        return "[sqlmap] no injection points found; target parameters not vulnerable"

    return "\n".join(candidates[:max_items])


def summarize_pre_hook_output(inject_as: str, payload: str | None, *, max_items: int = 30) -> str:
    """Compress one pre-hook tool output for the LLM context.

    Returns an empty string for empty payloads. Otherwise returns a
    truncated, denoised version capped at ``_HARD_LENGTH_CAP``
    characters.
    """
    if not payload or not isinstance(payload, str):
        return ""

    if _looks_like_nuclei(inject_as, payload):
        compact = _summarize_nuclei(payload, max_items=max_items)
    elif _looks_like_nikto(inject_as, payload):
        compact = _summarize_nikto(payload, max_items=max_items)
    elif _looks_like_sqlmap(inject_as, payload):
        compact = _summarize_sqlmap(payload, max_items=max_items)
    else:
        compact = payload

    if len(compact) > _HARD_LENGTH_CAP:
        compact = compact[:_HARD_LENGTH_CAP] + "\n... [truncated]"

    return compact


def imperative_findings_suffix(*, evidence_present: bool = True) -> str:
    """Short directive appended after the pre-hook evidence block.

    F185.C: cuando el block tiene findings, force el conversion.
    F203.AO.B: cuando el block está VACÍO (heurística-miss del catalog),
    NO emitir el "NO re-invocás" prohibitivo — eso causa que el modelo
    termine con `[]` sin intentar tools manuales. En su lugar, instruirlo
    a CONTINUAR con tools manuales target-specific.
    """
    if not evidence_present:
        return (
            "\n\n---\n"
            "**Pre-hook devolvió output VACÍO** (los detectores curated "
            "no matchearon este target específico). NO interpretes esto "
            "como 'target limpio'. **DEBÉS continuar** con tools manuales "
            "target-specific (`run_command` con curl/sqlmap/nuclei contra "
            "los endpoints reales del target). Solo emití findings JSON "
            "DESPUÉS de haber ejecutado al menos 3 tool calls manuales. "
            "NUNCA emitas `[]` directamente.\n"
        )
    from kryon.util.env import is_capable_model  # noqa: PLC0415

    if is_capable_model():
        # A capable model chains FROM confirmed leads — don't forbid re-invoking; the
        # perverse coupling was "better signal → tighter cage". Register the findings
        # AND keep driving.
        return (
            "\n\n---\n"
            "**Leads confirmados arriba (deterministic context).** Registrá cada uno "
            "como finding JSON (cwe + severity + host + rule_id + message + evidence) Y "
            "ENCADENÁ desde ellos hacia acceso/impacto: explotá cada lead, re-invocá "
            "nuclei/sqlmap con otros parámetros o endpoints si aporta, y perseguí toda "
            "lead abierta. No te limites a narrar lo ya recolectado.\n"
        )
    return (
        "\n\n---\n"
        "**ACCIÓN OBLIGATORIA**: convertí CADA línea del bloque "
        "deterministic context arriba en una entrada del array JSON de "
        "findings (cwe + severity + host + rule_id + message + evidence). "
        "NO re-invocás nuclei / nikto / sqlmap — la evidencia YA fue "
        "recolectada. Empezá el array JSON ahora.\n"
    )
