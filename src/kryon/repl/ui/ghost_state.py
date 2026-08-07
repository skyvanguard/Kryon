"""Ghost mood bus — the always-on Kryon eye that reacts to what it finds.

The Ghost eye (◆) lives persistently in the prompt marker and the bottom
toolbar. This module is the shared, thread-safe state that drives how it looks:

  * idle          → breathes steel-blue ↔ electric-cyan
  * after a find   → for a few seconds it throbs fast in the finding's severity
                     colour (an "alert"), then relaxes
  * remembers      → once something has been found this session, the idle
                     breathe tilts toward the highest severity seen (the Ghost
                     doesn't forget it saw a CRITICAL)

Producers (the spinner's tool hooks, engage, …) call `note_tool_output()` or
`react_finding()`. Consumers (prompt.py, toolbar.py) call `eye_pt_markup()` each
render tick. All access is lock-guarded; nothing here raises on bad input.
"""

from __future__ import annotations

import re
import threading
import time

from kryon.repl.ui.pulse import pulse_rgb

# Severity ordering + colours (aligned with the auditor palette used elsewhere).
_SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SEV_RGB: dict[str, tuple[int, int, int]] = {
    "INFO": (95, 139, 176),  # muted steel
    "LOW": (69, 224, 239),  # electric-cyan
    "MEDIUM": (234, 179, 8),  # amber
    "HIGH": (255, 140, 0),  # orange
    "CRITICAL": (239, 68, 68),  # red
}
_STEEL = (47, 110, 166)  # #2f6ea6
_CYAN = (69, 224, 239)  # #45e0ef

# How long the fast "alert" throb lasts after a fresh finding.
_FRESH_SECONDS = 9.0

_lock = threading.Lock()
_state: dict[str, object] = {
    "mood": "idle",  # idle | thinking
    "peak_severity": None,  # highest severity seen this session
    "fresh_until": 0.0,  # monotonic deadline for the fast alert throb
    "fresh_severity": None,  # severity of the most recent finding
    "findings": 0,  # session finding tally
}


def _now() -> float:
    return time.monotonic()


def set_mood(mood: str) -> None:
    """'thinking' while the agent works, 'idle' otherwise (future TUI use)."""
    with _lock:
        _state["mood"] = mood if mood in ("idle", "thinking") else "idle"


def react_finding(severity: str = "INFO", count: int = 1) -> None:
    """Register a finding: bump the tally, raise the session peak, and start
    a fresh fast-throb window in the finding's colour."""
    sev = (severity or "INFO").upper()
    if sev not in _SEV_RANK:
        sev = "INFO"
    with _lock:
        _state["findings"] = int(_state["findings"]) + max(1, count)  # type: ignore[arg-type]
        peak = _state["peak_severity"]
        if peak is None or _SEV_RANK[sev] > _SEV_RANK[str(peak)]:
            _state["peak_severity"] = sev
        _state["fresh_severity"] = sev
        _state["fresh_until"] = _now() + _FRESH_SECONDS


# Tools whose output we scan for severities, and the markers we look for.
_NUCLEI_SEV = re.compile(r"\[(critical|high|medium|low|info)\]", re.IGNORECASE)
_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)


def _line_at(text: str, idx: int) -> str:
    """The (trimmed) source line containing character offset `idx`."""
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    line = text[start:] if end == -1 else text[start:end]
    return line.strip()[:100]


def detect_findings(tool_name: str, output: str) -> list[tuple[str, str]]:
    """List of (severity, detail) findings recognized in a tool's output.

    Conservative: only fires on recognizable signals (nuclei severity tags,
    sqlmap 'is vulnerable', CVE ids). Empty when it sees nothing."""
    if not output:
        return []
    name = (tool_name or "").lower()
    # Cap the scanned slice: this runs on the event loop from on_tool_end with
    # the FULL (untruncated) tool output; a multi-MB nmap/nuclei dump would
    # stall streaming. Severity tags / CVEs surface early, so the head is enough.
    text = output[:20000]

    findings: list[tuple[str, str]] = []
    for m in _NUCLEI_SEV.finditer(text):
        findings.append((m.group(1).upper(), _line_at(text, m.start())))
    if findings:
        return findings

    lowered = text.lower()
    if "sqlmap" in name and "is vulnerable" in lowered:
        i = lowered.find("is vulnerable")
        return [("HIGH", _line_at(text, i) or "parameter is vulnerable")]
    cve = _CVE.search(text)
    if cve and ("vuln" in lowered or "exploit" in lowered):
        return [("MEDIUM", _line_at(text, cve.start()) or cve.group(0))]
    return []


def note_tool_output(tool_name: str, output: str) -> list[tuple[str, str]]:
    """Detect findings in a completed tool's output, react (bump the eye), and
    return the detected [(severity, detail), …] so the caller can flash them."""
    findings = detect_findings(tool_name, output)
    if findings:
        top = max((s for s, _ in findings), key=lambda s: _SEV_RANK[s])
        react_finding(top, count=len(findings))
    return findings


def fresh_reaction() -> str | None:
    """Severity of the current fast-throb window, or None when not reacting."""
    now = _now()
    with _lock:
        sev = _state["fresh_severity"]
        until = float(_state["fresh_until"])  # type: ignore[arg-type]
    return str(sev) if (sev and now < until) else None


def _lighten(rgb: tuple[int, int, int], t: float = 0.55) -> tuple[int, int, int]:
    return (
        int(rgb[0] + (255 - rgb[0]) * t),
        int(rgb[1] + (255 - rgb[1]) * t),
        int(rgb[2] + (255 - rgb[2]) * t),
    )


def _hex(rgb: tuple[int, int, int]) -> str:
    return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"


def eye_style() -> tuple[str, str]:
    """(glyph, hex) for the Ghost eye right now — reflects mood + reactions."""
    now = _now()
    with _lock:
        peak = _state["peak_severity"]
        fresh_sev = _state["fresh_severity"]
        fresh_until = float(_state["fresh_until"])  # type: ignore[arg-type]
        mood = str(_state["mood"])

    # Fresh finding → fast alert throb in the severity colour.
    if fresh_sev and now < fresh_until:
        base = _SEV_RGB[str(fresh_sev)]
        rgb = pulse_rgb(period=0.5, lo=base, hi=_lighten(base))
        glyph = "◈" if str(fresh_sev) in ("CRITICAL", "HIGH") else "◆"
        return glyph, _hex(rgb)

    # Idle breathe: toward cyan normally, or toward the session's peak severity
    # colour once something has been found (the Ghost remembers).
    hi = _SEV_RGB[str(peak)] if peak else _CYAN
    period = 1.2 if mood == "thinking" else 2.4
    rgb = pulse_rgb(period=period, lo=_STEEL, hi=hi)
    return "◆", _hex(rgb)


def eye_pt_markup() -> str:
    """prompt_toolkit HTML markup for the live eye — used by prompt + toolbar."""
    glyph, color = eye_style()
    return f'<style fg="{color}"><b>{glyph}</b></style>'


def findings_count() -> int:
    with _lock:
        return int(_state["findings"])  # type: ignore[arg-type]


def peak_severity() -> str | None:
    with _lock:
        peak = _state["peak_severity"]
        return str(peak) if peak else None


def reset() -> None:
    """Clear session reactions (new engagement / test helper)."""
    with _lock:
        _state.update(
            mood="idle",
            peak_severity=None,
            fresh_until=0.0,
            fresh_severity=None,
            findings=0,
        )
