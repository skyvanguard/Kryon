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


def _nuclei_severity(line: str) -> int:
    """Return the severity rank for a nuclei finding line. Unknown
    lines sort to the bottom."""
    m = _NUCLEI_LINE_RE.match(line)
    if not m:
        return _SEVERITY_RANK["unknown"]
    return _SEVERITY_RANK.get(m.group("severity").lower(), _SEVERITY_RANK["unknown"])


def _summarize_nuclei(payload: str, *, max_items: int) -> str:
    """Extract nuclei-shaped finding lines, sort by severity, cap to N."""
    candidates: list[str] = []
    for raw in payload.splitlines():
        line = raw.strip()
        if not line:
            continue
        if _NUCLEI_LINE_RE.match(line):
            candidates.append(line)
        # Other lines (banners, [INF] templates loaded, etc.) dropped.

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


def summarize_pre_hook_output(
    inject_as: str, payload: str | None, *, max_items: int = 30
) -> str:
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
    else:
        compact = payload

    if len(compact) > _HARD_LENGTH_CAP:
        compact = compact[:_HARD_LENGTH_CAP] + "\n... [truncated]"

    return compact


def imperative_findings_suffix() -> str:
    """Short directive appended after the pre-hook evidence block.

    The block above is the deterministic-tool output. F185.C bench
    showed the model often *acknowledges* the output without converting
    it to findings JSON. This suffix forces the conversion.
    """
    return (
        "\n\n---\n"
        "**ACCIÓN OBLIGATORIA**: convertí CADA línea del bloque "
        "deterministic context arriba en una entrada del array JSON de "
        "findings (cwe + severity + host + rule_id + message + evidence). "
        "NO re-invocás nuclei / nikto / sqlmap — la evidencia YA fue "
        "recolectada. Empezá el array JSON ahora.\n"
    )
