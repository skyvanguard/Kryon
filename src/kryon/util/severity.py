"""Canonical severity ranking (single source of truth).

El dict ``{"CRITICAL": 0, ..., "INFO": 4}`` estaba duplicado en ~30 sitios
(16 copias byte-idénticas como ``severity_order`` en ``tools/api/*``).
Centralizado acá para evitar drift (dos sitios ya habían divergido en el
valor de ``default``).
"""

from __future__ import annotations

import re

# Menor = más grave. Orden canónico para sort/comparación de findings.
SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

# Non-canonical labels the model (or an upstream tool) commonly emits.
_SEVERITY_ALIASES: dict[str, str] = {
    "CRIT": "CRITICAL",
    "ERROR": "CRITICAL",
    "SEVERE": "CRITICAL",
    "BLOCKER": "CRITICAL",
    "IMPORTANT": "HIGH",
    "MAJOR": "HIGH",
    "WARN": "MEDIUM",
    "WARNING": "MEDIUM",
    "MODERATE": "MEDIUM",
    "MED": "MEDIUM",
    "MINOR": "LOW",
    "INFORMATIONAL": "INFO",
    "INFORMATION": "INFO",
    "NOTE": "INFO",
    "NONE": "INFO",
    "NEGLIGIBLE": "INFO",
}


def severity_rank(severity: str, default: int = 99) -> int:
    """Rango ordenable de una severidad (case-insensitive). ``default`` para
    severidades desconocidas — 99 las manda al final del orden."""
    return SEVERITY_RANK.get((severity or "").upper(), default)


def normalize_severity(severity: str | float | int | None, default: str = "MEDIUM") -> str:
    """Map an arbitrary severity value to one of the 5 canonical labels.

    Accepts the canonical labels, common aliases (``ERROR``/``WARN``/
    ``informational``/…), embedded labels (``"Critical (CVSS 9.8)"``) and CVSS
    numeric scores (``"9.8"``, ``8.1``). NEVER fails — an unrecognized value falls
    back to ``default`` instead of the finding being dropped, which is what a bare
    ``if sev not in SEVERITY_RANK: continue`` did (a real CVE emitted as
    ``"9.8"`` or ``"informational"`` was silently lost)."""
    if severity is None:
        return default
    raw = str(severity).strip().upper()
    if not raw:
        return default
    if raw in SEVERITY_RANK:
        return raw
    if raw in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[raw]
    # Embedded canonical label, e.g. "CRITICAL (CVSS 9.8)" / "HIGH severity".
    for canon in SEVERITY_RANK:
        if canon in raw:
            return canon
    # Bare CVSS numeric.
    m = re.search(r"\d+(?:\.\d+)?", raw)
    if m:
        try:
            score = float(m.group())
        except ValueError:
            return default
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score >= 0.1:
            return "LOW"
        return "INFO"
    return default
