"""Canonical severity ranking (single source of truth).

El dict ``{"CRITICAL": 0, ..., "INFO": 4}`` estaba duplicado en ~30 sitios
(16 copias byte-idénticas como ``severity_order`` en ``tools/api/*``).
Centralizado acá para evitar drift (dos sitios ya habían divergido en el
valor de ``default``).
"""

from __future__ import annotations

# Menor = más grave. Orden canónico para sort/comparación de findings.
SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def severity_rank(severity: str, default: int = 99) -> int:
    """Rango ordenable de una severidad (case-insensitive). ``default`` para
    severidades desconocidas — 99 las manda al final del orden."""
    return SEVERITY_RANK.get((severity or "").upper(), default)
