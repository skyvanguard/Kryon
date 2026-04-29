"""
Claude-Code-style animated spinner for KRYON agent processing.

Ported from Claude Code's React/Ink spinner (src/components/Spinner/)
to Python/Rich. Features:

- Shimmer glyph animation (·✢✳✶✻✽) with RGB color interpolation
- Random spinner verbs ("Cogitating", "Clauding", "Concocting" …)
- Tool-call indication with command preview
- Stall detection — gradual red shift after 30s
- Elapsed time, LLM turn counter, recent tool history
"""

import functools
import math
import os
import random
import threading
import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.text import Text

_SENTINEL = object()

# ---------------------------------------------------------------------------
# Constants ported from Claude Code
# ---------------------------------------------------------------------------

# Glyph frames — same as Claude Code's getDefaultCharacters()
_GLYPHS_MACOS = ["·", "✢", "✳", "✶", "✻", "✽"]
_GLYPHS_OTHER = ["·", "✢", "*", "✶", "✻", "✽"]
_GLYPHS = _GLYPHS_MACOS if os.name != "nt" else _GLYPHS_OTHER
# Ping-pong: forward then reverse (like Claude Code)
_GLYPH_FRAMES = [*_GLYPHS, *reversed(_GLYPHS)]

# Shimmer timing
_REFRESH_MS = 80  # animation tick (~12 fps)
_SHIMMER_CYCLE_MS = 1600  # one full shimmer wave
_STALL_THRESHOLD_S = 30  # start turning red

# Colors (RGB tuples)
_COLOR_ACTIVE = (99, 102, 241)  # indigo-500 — the default "thinking" color
_COLOR_SHIMMER_PEAK = (165, 180, 252)  # indigo-300
_COLOR_STALLED = (239, 68, 68)  # red-500
_COLOR_DIM = (120, 120, 120)
_COLOR_TOOL = (34, 197, 94)  # green-500
_COLOR_HANDOFF = (250, 204, 21)  # yellow-400

# Spinner verbs (subset of Claude Code's spinnerVerbs.ts)
_VERBS = [
    "Thinking",
    "Analyzing",
    "Architecting",
    "Brewing",
    "Calculating",
    "Cerebrating",
    "Clauding",
    "Cogitating",
    "Computing",
    "Concocting",
    "Contemplating",
    "Crafting",
    "Crunching",
    "Crystallizing",
    "Deciphering",
    "Deliberating",
    "Envisioning",
    "Evaluating",
    "Fermenting",
    "Formulating",
    "Hacking",
    "Investigating",
    "Manifesting",
    "Materializing",
    "Meditating",
    "Musing",
    "Orchestrating",
    "Pondering",
    "Processing",
    "Reasoning",
    "Reflecting",
    "Ruminating",
    "Scheming",
    "Scrutinizing",
    "Simmering",
    "Synthesizing",
    "Transmuting",
    "Unraveling",
    "Weaving",
    "Whittling",
]


# ---------------------------------------------------------------------------
# Color math
# ---------------------------------------------------------------------------

def _lerp_rgb(
    c1: tuple[int, int, int],
    c2: tuple[int, int, int],
    t: float,
) -> tuple[int, int, int]:
    """Linearly interpolate between two RGB colors (t in 0..1)."""
    return (
        int(c1[0] + (c2[0] - c1[0]) * t),
        int(c1[1] + (c2[1] - c1[1]) * t),
        int(c1[2] + (c2[2] - c1[2]) * t),
    )


def _rgb_style(r: int, g: int, b: int) -> str:
    """Convert RGB to a Rich inline color string."""
    return f"rgb({r},{g},{b})"


def _shimmer_color(
    elapsed_ms: float,
    char_index: int,
    stall_t: float,
) -> tuple[int, int, int]:
    """Compute the shimmer color for one character at the current time.

    Replicates Claude Code's phase-offset sine-wave shimmer, with a
    gradual blend toward red when stalled.
    """
    # Phase offset per character creates the "wave" effect
    phase = (elapsed_ms / _SHIMMER_CYCLE_MS + char_index * 0.12) % 1.0
    # Sine curve 0→1→0 within one cycle
    wave = (math.sin(phase * math.pi * 2) + 1) / 2

    base = _lerp_rgb(_COLOR_ACTIVE, _COLOR_SHIMMER_PEAK, wave)
    if stall_t > 0:
        base = _lerp_rgb(base, _COLOR_STALLED, min(stall_t, 1.0))
    return base


# ---------------------------------------------------------------------------
# Tool summary extraction (one-liner from tool output)
# ---------------------------------------------------------------------------


def _extract_tool_summary(tool_name: str, output: str) -> str:
    """Extract a brief one-liner summary from a tool's output."""
    import re

    if not output or len(output) < 5:
        return "done"

    lower_out = output.lower()
    clean_name = tool_name.rsplit(":", 1)[-1] if ":" in tool_name else tool_name

    if clean_name == "nmap" or "nmap" in clean_name:
        ports = len(re.findall(r"\d+/tcp\s+open", output))
        return f"{ports} ports open" if ports else "no open ports"

    if "whatweb" in clean_name:
        techs = re.findall(r"(?:HTTPServer|Title|Apache|nginx|PHP|WordPress|Bootstrap|jQuery)\[([^\]]+)\]", output)
        return ", ".join(techs[:4]) if techs else "scanned"

    if "recall_similar" in clean_name:
        m = re.search(r"'count':\s*(\d+)", output)
        count = int(m.group(1)) if m else 0
        return f"{count} prior experiences" if count else "cold start"

    if "gobuster" in clean_name or "dirb" in clean_name:
        dirs = len(re.findall(r"Status:\s*2\d\d", output))
        return f"{dirs} directories" if dirs else "no dirs found"

    if "nuclei" in clean_name:
        findings = len(re.findall(r"\[(?:critical|high|medium|low|info)\]", lower_out))
        return f"{findings} findings" if findings else "clean"

    if "duckduckgo" in clean_name:
        results = len(re.findall(r"'title':", output))
        return f"{results} results"

    if "error" in lower_out[:200]:
        return "error"

    return "done"


# ---------------------------------------------------------------------------
# AgentSpinner
# ---------------------------------------------------------------------------


class AgentSpinner:
    """Thread-safe Claude-Code-style spinner for agent processing.

    Drop-in replacement for the previous Rich Status-based spinner.
    Same public API: start(), stop(), update(), create_hooks(),
    patch_model(), patch_tools(), context manager.
    """

    def __init__(self, agent_name: str, console: Console):
        self._agent_name = agent_name
        self._console = console
        self._live: Live | None = None
        self._thread: threading.Thread | None = None
        self._started = threading.Event()
        self._stop_event = threading.Event()
        self._start_time: float = 0
        self._tool_name: str | None = None
        self._handoff_agent: str | None = None
        self._tools_run: list[str] = []
        self._tool_results: list[tuple[str, str, str]] = []  # (name, status, summary)
        self._active_skill: str | None = None
        self._llm_turn: int = 0
        self._progress_state: Any = None
        self._lock = threading.Lock()
        self._patched_models: list[tuple] = []
        self._patched_tools: list[tuple] = []
        self._verb = random.choice(_VERBS)
        self._verb_last_change = 0.0
        self._frame_idx = 0

    # ------------------------------------------------------------------
    # Time formatting
    # ------------------------------------------------------------------

    @staticmethod
    def _format_elapsed(seconds: float) -> str:
        minutes, secs = divmod(int(seconds), 60)
        if minutes > 0:
            return f"{minutes}m {secs}s"
        return f"{secs}s"

    # ------------------------------------------------------------------
    # Render one frame
    # ------------------------------------------------------------------

    def _render_frame(self) -> Text:
        now = time.monotonic()
        elapsed_s = now - self._start_time
        elapsed_ms = elapsed_s * 1000

        # Rotate verb every ~8 seconds
        if now - self._verb_last_change > 8:
            self._verb = random.choice(_VERBS)
            self._verb_last_change = now

        # Stall factor (0 = normal, 1 = fully stalled after 60s)
        stall_t = max(0, (elapsed_s - _STALL_THRESHOLD_S) / 30)

        # Advance glyph frame
        self._frame_idx = int(elapsed_ms / 120) % len(_GLYPH_FRAMES)
        glyph = _GLYPH_FRAMES[self._frame_idx]

        result = Text()

        # ── Shimmer glyph ──
        glyph_color = _shimmer_color(elapsed_ms, 0, stall_t)
        result.append(f" {glyph} ", style=f"bold {_rgb_style(*glyph_color)}")

        # ── Agent name (shimmer each char independently) ──
        display_name = self._handoff_agent or self._agent_name
        for i, ch in enumerate(display_name):
            c = _shimmer_color(elapsed_ms, i + 1, stall_t)
            result.append(ch, style=f"bold {_rgb_style(*c)}")

        # ── Active skill indicator ──
        if self._active_skill:
            result.append(f" [{self._active_skill}]", style="dim cyan")

        result.append(" ", style="")

        # F77.D / Fase 10: spinner ahora SOLO muestra "agente vivo" — verbo +
        # turn counter + elapsed. Las tool invocations/completions las imprime
        # el renderer plano (Fase 1/3/8) que muestra args y duraciones reales,
        # así no duplicamos la lista de tools sobre el output ya impreso.
        for i, ch in enumerate(self._verb):
            c = _shimmer_color(elapsed_ms, i + len(display_name) + 2, stall_t)
            result.append(ch, style=_rgb_style(*c))
        result.append("…", style=f"dim {_rgb_style(*_COLOR_DIM)}")

        if self._llm_turn > 1:
            result.append(f" turn {self._llm_turn}", style=f"dim {_rgb_style(*_COLOR_DIM)}")

        # ── Elapsed ──
        elapsed_str = self._format_elapsed(elapsed_s)
        if elapsed_s >= 120:
            result.append(f"  ({elapsed_str} — Ctrl+C)", style="bold red")
        else:
            result.append(f"  ({elapsed_str})", style=f"dim {_rgb_style(*_COLOR_DIM)}")

        return result

    # ------------------------------------------------------------------
    # Background thread
    # ------------------------------------------------------------------

    def _run(self) -> None:
        self._start_time = time.monotonic()
        self._verb_last_change = self._start_time
        self._live = Live(
            self._render_frame(),
            console=self._console,
            refresh_per_second=int(1000 / _REFRESH_MS),
            transient=True,
        )
        self._live.start()
        self._started.set()

        while not self._stop_event.is_set():
            try:
                with self._lock:
                    frame = self._render_frame()
                self._live.update(frame)
            except Exception:
                pass
            self._stop_event.wait(_REFRESH_MS / 1000)

        try:
            self._live.stop()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._started.wait()

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop_event.set()
        self._thread.join(timeout=1)
        self._thread = None
        self._live = None
        for model, original in self._patched_models:
            model.get_response = original
        self._patched_models.clear()
        for tool, original in self._patched_tools:
            tool.on_invoke_tool = original
        self._patched_tools.clear()

    def request_stop(self) -> None:
        """Signal stop without blocking — safe from async context."""
        self._stop_event.set()

    def update(
        self,
        *,
        tool_name: object = _SENTINEL,
        handoff_agent: object = _SENTINEL,
    ) -> None:
        with self._lock:
            if tool_name is not _SENTINEL:
                self._tool_name = tool_name  # type: ignore[assignment]
            if handoff_agent is not _SENTINEL:
                self._handoff_agent = handoff_agent  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Model patching
    # ------------------------------------------------------------------

    def patch_model(self, model) -> None:
        if not hasattr(model, "get_response"):
            return
        original = model.get_response
        spinner = self

        @functools.wraps(original)
        async def wrapped(*args, **kwargs):
            with spinner._lock:
                spinner._llm_turn += 1
            try:
                return await original(*args, **kwargs)
            finally:
                pass

        model.get_response = wrapped
        self._patched_models.append((model, original))

    # ------------------------------------------------------------------
    # Tool patching
    # ------------------------------------------------------------------

    def patch_tools(self, tools) -> None:
        import json as _json

        for tool in tools:
            if not (hasattr(tool, "name") and tool.name == "run_command"):
                continue
            if not hasattr(tool, "on_invoke_tool"):
                continue
            original_invoke = tool.on_invoke_tool
            spinner = self

            async def wrapped_invoke(ctx, input_json_str, _orig=original_invoke, _spinner=spinner):
                try:
                    args = _json.loads(input_json_str)
                    cmd = args.get("command", "")
                    if cmd:
                        display = cmd[:50] + "…" if len(cmd) > 50 else cmd
                        _spinner.update(tool_name=f"run_command: {display}")
                except Exception:
                    pass
                return await _orig(ctx, input_json_str)

            tool.on_invoke_tool = wrapped_invoke
            self._patched_tools.append((tool, original_invoke))

    # ------------------------------------------------------------------
    # Hooks factory
    # ------------------------------------------------------------------

    def create_hooks(self):
        from kryon.sdk.agents.lifecycle import RunHooks

        spinner = self

        class SpinnerRunHooks(RunHooks):
            async def on_tool_start(self, context, agent, tool):
                # F77.D / Fase 10: tool start line is now printed by the SDK
                # adapter's `▸ tool args` (Fase 8). The spinner only tracks
                # internal state for the elapsed/turn header.
                name = getattr(tool, "name", None) or str(tool)
                spinner.update(tool_name=name)

            async def on_tool_end(self, context, agent, tool, result):
                # F77.D / Fase 10: completion line is printed by
                # cli_print_tool_output → _render_simple_tool_completion
                # (Fase 6). We still track tools_run for diagnostics.
                name = getattr(tool, "name", None) or str(tool)
                result_str = str(result) if result else ""
                status = "error" if "error" in result_str.lower()[:200] else "ok"
                with spinner._lock:
                    spinner._tools_run.append(name)
                    spinner._tool_results.append(
                        (name, status, _extract_tool_summary(name, result_str)),
                    )
                    spinner._tool_name = None

            async def on_handoff(self, context, from_agent, to_agent):
                to_name = getattr(to_agent, "name", None) or str(to_agent)
                spinner.update(handoff_agent=to_name)
                try:
                    spinner._console.print(f"[dim cyan]⤳ handoff →[/dim cyan] {to_name}")
                except Exception:
                    pass

        return SpinnerRunHooks()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "AgentSpinner":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
