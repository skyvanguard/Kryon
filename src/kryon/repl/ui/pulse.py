"""Time-based color pulse for the REPL's "alive" chrome.

A single sine wave over wall-clock time interpolates between two crystalline
shades (steel-blue ↔ electric-cyan), so the prompt marker and the toolbar eye
can breathe in sync without any per-widget state. Pure + cheap; safe to call on
every render tick.
"""

from __future__ import annotations

import math
import time

_STEEL = (47, 110, 166)  # #2f6ea6
_CYAN = (69, 224, 239)  # #45e0ef
_PULSE_STEPS = 10  # quantize the pulse → fewer distinct frames → fewer redraws


def _lerp(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return (
        int(a[0] + (b[0] - a[0]) * t),
        int(a[1] + (b[1] - a[1]) * t),
        int(a[2] + (b[2] - a[2]) * t),
    )


def pulse_rgb(
    period: float = 2.4,
    lo: tuple[int, int, int] = _STEEL,
    hi: tuple[int, int, int] = _CYAN,
    phase: float = 0.0,
) -> tuple[int, int, int]:
    """RGB somewhere between `lo` and `hi`, oscillating with `period` seconds.

    The wave is quantized to a handful of steps (C3): consecutive render ticks
    then usually produce the SAME colour, so the toolbar/prompt markup doesn't
    change every tick and prompt_toolkit skips the redraw — much less flicker on
    slow terminals / over SSH, while the pulse still reads as smooth."""
    ph = ((time.monotonic() / period) + phase) % 1.0
    wave = (math.sin(ph * 2 * math.pi) + 1) / 2
    wave = round(wave * _PULSE_STEPS) / _PULSE_STEPS
    return _lerp(lo, hi, wave)


def pulse_hex(period: float = 2.4, phase: float = 0.0) -> str:
    """`#rrggbb` breathing steel-blue ↔ electric-cyan over `period` seconds."""
    r, g, b = pulse_rgb(period=period, phase=phase)
    return f"#{r:02x}{g:02x}{b:02x}"
