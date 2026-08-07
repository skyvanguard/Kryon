"""Env-driven config for the Lynis integration.

* Fire gate — ``KRYON_LYNIS_FIRE`` (default OFF). Lynis is read-only, but gating
  it keeps every external-scan integration uniform and opt-in.
* Suggestions — Lynis emits many advisory suggestions; ``KRYON_LYNIS_SUGGESTIONS``
  (default on) controls whether they become (LOW) findings.
"""

from __future__ import annotations

import os

_TRUTHY = {"1", "true", "yes", "on"}


def is_lynis_enabled() -> bool:
    """True only when KRYON_LYNIS_FIRE opts in. Default OFF."""
    return os.getenv("KRYON_LYNIS_FIRE", "").strip().lower() in _TRUTHY


def include_suggestions() -> bool:
    """Whether Lynis suggestions become LOW findings (default on)."""
    return os.getenv("KRYON_LYNIS_SUGGESTIONS", "true").strip().lower() in _TRUTHY
