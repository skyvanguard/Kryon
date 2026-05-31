"""Canonical env-var parsing helpers (single source of truth).

El idiom truthy ``os.environ.get(name, ...).strip().lower() in {"1","true",
"yes","on"}`` estaba reimplementado en ~17 sitios (varios como ``_env_bool``
local idéntico) con defaults inconsistentes. Centralizado acá.
"""

from __future__ import annotations

import os

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def env_bool(name: str, default: bool = False) -> bool:
    """True si la env var ``name`` está seteada a un valor truthy
    (``1``/``true``/``yes``/``on``, case-insensitive). ``default`` si está
    ausente o vacía."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in _TRUTHY
