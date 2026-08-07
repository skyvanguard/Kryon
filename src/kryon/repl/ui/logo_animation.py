"""Kryon boot-up logo animation — the crystalline "Ghost" waking up.

Renders a solid faceted shell — a diamond of angular steel-blue plates with a
central glowing eye (electric-cyan), lit from the top-left like
``assets/kryon-mark.svg`` — evoking the Ghost-of-Destiny companion. The boot-up
is a multi-stage "awakening":

  1. particles flicker in the dark and converge toward the center
  2. the eye opens and its iris dilates
  3. the shell assembles from the core outward (body → edges → points)
  4. a sweep of light travels the perimeter with a motion-blur trail
  5. a scan beam sweeps across the shell (the Ghost scanning its target)
  6. it breathes (a soft double pulse), then the wordmark settles in

Emblem (awake):

        ▲
      ◤███◥
    ◀███◉███▶
      ◣███◢
        ▼

Guards: silently skipped when stdout isn't a TTY (pipes / CI) or
KRYON_NO_ANIMATION is set. Ctrl+C during the animation skips to the final frame
(never crashes the REPL start).
"""

from __future__ import annotations

import os
import sys
import time

from rich.console import Console
from rich.text import Text

# Crystalline palette (matches assets/kryon-mark.svg: lit facets #2f6ea6,
# shadow facets darker, electric-cyan seams/eye #45e0ef).
_LIT = "#4a97d6"  # plate lit by the top-left light (bright)
_SHADOW = "#2f6ea6"  # plate in shadow (lower-right) — still clearly painted
_TRAIL_1 = "#7fb3e0"  # motion-blur trail, one step behind the sweep
_TRAIL_2 = "#4a97d6"  # motion-blur trail, two steps behind
_SUBTLE = "#5f8bb0"  # subtitle text to the right of the emblem
_SWEEP = "bold #7fd4e8"  # the plate the light sweep is crossing
_CORE = "bold #45e0ef"  # the eye, awake
_CORE_DIM = "#2a7f8c"  # the eye, breathing out
_BEAM = "bold #45e0ef"  # scan beam
_DUST = "#2a7f8c"  # converging particles
_WORD = "bold #45e0ef"

_PAD = "   "  # left margin

# Emblem geometry on a 5-row × 9-col grid. A solid diamond of plates around a
# central eye; cols 0/1 and 7/8 outside the diamond form the halo (dust/beam).
_N_ROWS = 5
_N_COLS = 9
_EYE_RC = (2, 4)
_PLATES: dict[tuple[int, int], str] = {
    (0, 4): "▲",
    (1, 2): "◤", (1, 3): "█", (1, 4): "█", (1, 5): "█", (1, 6): "◥",
    (2, 0): "◀", (2, 1): "█", (2, 2): "█", (2, 3): "█",
    (2, 5): "█", (2, 6): "█", (2, 7): "█", (2, 8): "▶",
    (3, 2): "◣", (3, 3): "█", (3, 4): "█", (3, 5): "█", (3, 6): "◢",
    (4, 4): "▼",
}  # fmt: skip

# Perimeter cells, clockwise from the top point — the light sweep's path.
_PERIM: list[tuple[int, int]] = [
    (0, 4), (1, 6), (2, 8), (3, 6), (4, 4), (3, 2), (2, 0), (1, 2),
]  # fmt: skip

# Assembly order: body nearest the eye first, then outward, then edges, then
# the four points. Gives a "core solidifies, then the shell extends" reveal.
_REVEAL: list[tuple[int, int]] = [
    (1, 4), (3, 4), (2, 3), (2, 5),  # body ring 1
    (1, 3), (1, 5), (3, 3), (3, 5), (2, 2), (2, 6),  # body ring 2
    (2, 1), (2, 7),  # body ring 3
    (1, 2), (1, 6), (3, 2), (3, 6),  # edges
    (0, 4), (2, 8), (2, 0), (4, 4),  # points
]  # fmt: skip

# Halo cells (neither plate nor eye) — where dust + the scan beam live.
_HALO: list[tuple[int, int]] = [
    (r, c) for r in range(_N_ROWS) for c in range(_N_COLS) if (r, c) != _EYE_RC and (r, c) not in _PLATES
]
# Converge order: outermost (by Chebyshev distance from the eye) first.
_DUST_ORDER = sorted(_HALO, key=lambda rc: (-max(abs(rc[0] - 2), abs(rc[1] - 4)), rc))


def should_animate() -> bool:
    if os.getenv("KRYON_NO_ANIMATION", "").strip().lower() in ("1", "true", "yes", "on"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:  # noqa: BLE001
        return False


def _iris(level: int) -> str:
    # 0 dark · 1 spark · 2 pinhole · 3 half · 4 eye open · 5 dilated
    return (" ", "·", "◦", "⊙", "◉", "◎")[max(0, min(5, level))]


def _plate_style(r: int, c: int) -> str:
    """Lit from the top-left: upper/left plates lit, lower/right in shadow."""
    return _SHADOW if (r > 2 or c > 4) else _LIT


def _frame(
    *,
    iris: int,
    core_style: str = _CORE,
    shown: set[tuple[int, int]] | None = None,  # plate cells drawn; None = all
    trail: dict[tuple[int, int], str] | None = None,  # cell -> highlight style
    overlay: dict[tuple[int, int], tuple[str, str]] | None = None,  # halo glyphs
    beam_col: int | None = None,
    right_lines: dict[int, tuple[str, str]] | None = None,  # emblem row -> (text, style)
) -> Text:
    """Build one animation frame as a Rich Text block.

    `right_lines` maps an emblem row index to text placed to the RIGHT of that
    row (used at settle to lay the wordmark + tagline beside the shell).
    """
    trail = trail or {}
    overlay = overlay or {}
    right_lines = right_lines or {}

    t = Text()
    for r in range(_N_ROWS):
        t.append(_PAD)
        for c in range(_N_COLS):
            rc = (r, c)
            in_beam = beam_col is not None and c == beam_col
            if rc == _EYE_RC:
                t.append(_iris(iris), style=_BEAM if (in_beam and iris) else core_style)
            elif rc in _PLATES and (shown is None or rc in shown):
                if in_beam:
                    style = _BEAM
                elif rc in trail:
                    style = trail[rc]
                else:
                    style = _plate_style(r, c)
                t.append(_PLATES[rc], style=style)
            elif rc in overlay:
                glyph, style = overlay[rc]
                t.append(glyph, style=style)
            elif in_beam:
                t.append("┃", style=_BEAM)
            else:
                t.append(" ")
        if r in right_lines:
            text_, style = right_lines[r]
            t.append("   ")  # gap between shell and text
            t.append(text_, style=style)
        t.append("\n")
    return t


def _final_frame(wordmark: str = "", subtitle_lines: list[tuple[str, str]] | None = None) -> Text:
    """Settled shell with the wordmark + tagline laid out to its right,
    vertically centered against the 5-row emblem."""
    right = {1: (wordmark, _WORD)}
    for offset, line in enumerate(subtitle_lines or []):
        right[2 + offset] = line
    return _frame(iris=4, core_style=_CORE, shown=None, right_lines=right)


def render_logo_animation(
    console: Console,
    *,
    version: str,
    codename: str,
    subtitle_lines: list[tuple[str, str]] | None = None,
) -> None:
    """Play the Ghost awakening, then settle with the wordmark + optional
    `subtitle_lines` laid out to the right of the shell. No-op (static frame)
    when animation is disabled."""
    wordmark = f"◇ KRYON  v{version} · {codename}"

    if not should_animate():
        console.print(_final_frame(wordmark, subtitle_lines))
        return

    from rich.live import Live

    try:
        with Live(console=console, refresh_per_second=30, transient=False) as live:
            # Phase 1 — particles flicker and converge toward the center.
            n_dust = len(_DUST_ORDER)
            for step in range(n_dust, 0, -2):
                overlay = dict.fromkeys(_DUST_ORDER[:step], ("·", _DUST))
                live.update(_frame(iris=1 if step < n_dust // 2 else 0, shown=set(), overlay=overlay))
                time.sleep(0.03)

            # Phase 2 — the eye opens and its iris dilates.
            for lvl in (1, 2, 3, 4, 5, 4):
                live.update(_frame(iris=lvl, shown=set()))
                time.sleep(0.07)

            # Phase 3 — the shell assembles from the core outward.
            shown: set[tuple[int, int]] = set()
            for i in range(0, len(_REVEAL), 2):
                shown.update(_REVEAL[i : i + 2])
                live.update(_frame(iris=4, shown=set(shown)))
                time.sleep(0.045)

            # Phase 4 — a light sweep travels the perimeter, twice, with a trail.
            for i in range(len(_PERIM) * 2):
                head = _PERIM[i % len(_PERIM)]
                t1 = _PERIM[(i - 1) % len(_PERIM)]
                t2 = _PERIM[(i - 2) % len(_PERIM)]
                trail = {t2: _TRAIL_2, t1: _TRAIL_1, head: _SWEEP}
                live.update(_frame(iris=4, trail=trail))
                time.sleep(0.055)

            # Phase 5 — a scan beam sweeps across (the Ghost scanning its target).
            for c in list(range(_N_COLS)) + list(range(_N_COLS - 2, -1, -1)):
                live.update(_frame(iris=4, beam_col=c))
                time.sleep(0.03)

            # Phase 6 — it breathes (soft double pulse).
            for iris, core in ((5, _CORE_DIM), (4, _CORE), (5, _CORE_DIM), (4, _CORE)):
                live.update(_frame(iris=iris, core_style=core))
                time.sleep(0.11)

            # Phase 7 — settle: wordmark + tagline slide in to the right.
            live.update(_final_frame(wordmark, subtitle_lines))
            time.sleep(0.15)
    except KeyboardInterrupt:
        console.print(_final_frame(wordmark, subtitle_lines))
