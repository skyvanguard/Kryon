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


def is_red_team() -> bool:
    """Single source of truth for the KRYON_RED_TEAM offensive gate. Use this
    everywhere instead of re-parsing the env var — the ad-hoc variants
    (``in ("1","true","yes")`` without ``on``, with/without ``.strip()``) caused
    a 'half-open' gate where ``KRYON_RED_TEAM=on`` enabled some active modules
    but not others."""
    return env_bool("KRYON_RED_TEAM")
