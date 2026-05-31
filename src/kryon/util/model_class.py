"""Canonical model defaults + reasoning-class detection (single source of truth).

Consolida las dos copias de ``is_reasoning_model`` que vivían en
``policy/preflight.py`` y ``tools/autonomous/pentest_planner.py``. Sus tuplas de
markers ya habían divergido (una reconocía ``o1``/``o3`` y la otra no), lo que
producía que un mismo modelo se tratara como reasoning para el turn-cap pero
como instruct para las gates de grounding. Una sola definición evita ese drift.
"""

from __future__ import annotations

import os

# Default local-only. NUNCA debe ser un frontier API (banca: sin fuga de datos
# a terceros). El runtime real lo fija KRYON_MODEL; esto es el fallback.
DEFAULT_MODEL = "Kryon-MOE-35B"

# Substrings (case-insensitive) que marcan un modelo como reasoning-class
# (chain-of-thought visible → bump de turnos por fase + gates de grounding).
REASONING_MARKERS: tuple[str, ...] = (
    "moe",  # Kryon-MOE-35B (Qwen3.6-35B-A3B) emite <think>
    "r1-",
    "-r1",
    "deepseek-r1",
    "reasoning",
    "foundation-sec",
    "o1",
    "o3",
)


def is_reasoning_model(model: str | None) -> bool:
    """True cuando el modelo emite chain-of-thought visible."""
    if not model:
        return False
    lowered = model.lower()
    return any(marker in lowered for marker in REASONING_MARKERS)


def default_model() -> str:
    """Modelo efectivo: ``KRYON_MODEL`` o el default local."""
    return os.environ.get("KRYON_MODEL", DEFAULT_MODEL)
