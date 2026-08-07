"""
Module for the KRYON REPL toolbar functionality.
"""

import datetime
import os
import platform
import shutil
import socket
import subprocess
import threading
from functools import lru_cache

from prompt_toolkit.formatted_text import HTML  # pylint: disable=import-error

# Variable to track when to refresh the toolbar
toolbar_last_refresh = [datetime.datetime.now()]

# Cache for toolbar data
toolbar_cache = {
    "html": "",
    "last_update": datetime.datetime.now(),
    "refresh_interval": 5,  # Refresh every 5 seconds
    "context_warning_shown": False,  # Track if we've shown context warning
}

# Only ONE background rebuild at a time. The prompt's refresh_interval fires
# get_toolbar_with_refresh ~2x/sec; without this, a slow rebuild (e.g. a wedged
# `docker inspect`) would let each tick spawn another thread → a thread +
# subprocess storm. Non-blocking acquire: extra triggers no-op instantly.
_update_lock = threading.Lock()

# Cache for system information that rarely changes
system_info = {"ip_address": None, "os_name": None, "os_version": None}


@lru_cache(maxsize=1)
def get_system_info():
    """Get system information that rarely changes (cached)."""
    if not system_info["ip_address"]:
        try:
            # Get local IP addresses
            hostname = socket.gethostname()
            system_info["ip_address"] = socket.gethostbyname(hostname)

            # Get OS information
            system_info["os_name"] = platform.system()
            system_info["os_version"] = platform.release()
        except Exception:  # pylint: disable=broad-except
            system_info["ip_address"] = "unknown"
            system_info["os_name"] = "unknown"
            system_info["os_version"] = "unknown"

    return system_info


def get_terminal_width():
    """Get the terminal width."""
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80  # Default width


# The real (behind-the-alias) served model — shared with banner + `kryon config`.
from kryon.util.model_probe import real_model_name  # noqa: E402


def _get_kryon_state_str(compact: bool = False) -> str:
    """Build the Kryon-specific runtime block for the toolbar.

    Reads from runtime_state (shared with the REPL loop) + the cached
    helpers in status_line. All look-ups degrade silently to empty
    strings — toolbar updater must never raise.
    """
    try:
        from kryon.repl.ui.runtime_state import (
            get_active_skill_names,
            get_tool_count,
        )
        from kryon.repl.ui.status_line import _cached, _count_drafts
    except Exception:  # pragma: no cover
        return ""

    parts: list[str] = []

    # Skills / tools — primary accent (electric-cyan seam #45e0ef).
    try:
        skills = get_active_skill_names()
        tool_count = get_tool_count()
        # «EYE» is a placeholder swapped for a pulsing ◆ in get_bottom_toolbar
        # (a soft heartbeat so the toolbar feels alive). Kept OUTSIDE the cyan
        # span so the live color wins.
        if compact:
            label = f'«EYE» <style fg="#45e0ef">{len(skills)}sk/{tool_count}t</style>'
        else:
            label = f'«EYE» <style fg="#45e0ef"><b>Skills:</b> {len(skills)} ({tool_count} tools)</style>'
        parts.append(label)
    except Exception:  # pragma: no cover
        pass

    # Drafts pendientes — secondary accent (steel-blue #2f6ea6).
    try:
        n = _cached("drafts", _count_drafts)
        if n:
            text_ = f"📝 {n}" if compact else f"<b>📝 Drafts:</b> {n}"
            parts.append(f'<style fg="#2f6ea6">{text_}</style>')
    except Exception:  # pragma: no cover
        pass

    # Findings the Ghost reacted to this session — badge in the peak-severity
    # colour so it stays visible after the eye's throb decays.
    try:
        from kryon.repl.ui.ghost_state import findings_count, peak_severity

        n = findings_count()
        if n:
            sev = peak_severity() or "INFO"
            sev_color = {
                "CRITICAL": "#ef4444",
                "HIGH": "#ff8c00",
                "MEDIUM": "#eab308",
                "LOW": "#45e0ef",
                "INFO": "#5f8bb0",
            }.get(sev, "#45e0ef")
            text_ = f"⚑{n}" if compact else f"<b>⚑ {n} findings</b>"
            parts.append(f'<style fg="{sev_color}">{text_}</style>')
    except Exception:  # pragma: no cover
        pass

    return " | ".join(parts) if parts else ""


def _phase_turn_cap() -> str:
    """Operative per-phase turn cap (F166) — the budget actually in effect.

    Resolved from KRYON_PHASE_TURNS (operator override) or the model class
    (reasoning → 8, instruct → 5). Delegates to the single-source resolver
    so the toolbar never drifts from the planner; degrades to '?' on any
    failure (the toolbar must never raise).
    """
    try:
        from kryon.tools.autonomous.pentest_planner import resolve_phase_turn_cap

        return str(resolve_phase_turn_cap())
    except Exception:  # pragma: no cover - light fallback mirroring the resolver
        override = os.getenv("KRYON_PHASE_TURNS", "").strip()
        if override.isdigit() and int(override) > 0:
            return override
        try:
            from kryon.util.model_class import is_reasoning_model

            return "8" if is_reasoning_model(os.getenv("KRYON_MODEL", "")) else "5"
        except Exception:
            return "?"


def update_toolbar_in_background():
    """Update the toolbar cache in a background thread."""
    # Skip if a rebuild is already running — prevents the thread pileup.
    if not _update_lock.acquire(blocking=False):
        return
    try:
        # Get system info (cached)
        sys_info = get_system_info()
        sys_info["ip_address"]
        sys_info["os_name"]
        sys_info["os_version"]

        # Get the current workspace and base directory
        workspace_name = os.getenv("KRYON_WORKSPACE")
        base_dir = os.getenv("KRYON_WORKSPACE_DIR", "workspaces")

        # Construct the workspace path
        standard_path = os.path.join(base_dir, workspace_name) if workspace_name else ""
        if workspace_name:
            if os.path.isdir(standard_path):
                pass
            elif os.path.isdir(workspace_name):
                os.path.abspath(workspace_name)
            else:
                pass

        # Get current active container info
        container_id = os.getenv("KRYON_ACTIVE_CONTAINER")
        if container_id:
            active_env_name, active_env_icon, active_env_color = get_container_info(container_id)
        else:
            active_env_name, active_env_icon, active_env_color = "Host System", "💻", "ansiblue"

        # Get current time for the toolbar refresh indicator
        current_time = datetime.datetime.now().strftime("%H:%M")

        # Add timezone information to show it's local time
        timezone_name = datetime.datetime.now().astimezone().tzname()
        current_time_with_tz = f"{current_time} {timezone_name}"

        # Get auto-compact status and context usage
        auto_compact = os.getenv("KRYON_AUTO_COMPACT", "true").lower() == "true"

        # Try to get context usage from environment (set by openai_chatcompletions.py)
        context_usage = 0.0
        try:
            context_usage = float(os.getenv("KRYON_CONTEXT_USAGE", "0.0"))
        except Exception:
            pass

        # Determine auto-compact display based on usage
        if auto_compact:
            if context_usage >= 0.8:  # Above 80%
                auto_compact_str = f"⚠️ {int(context_usage * 100)}%"
                auto_compact_color = "ansired"  # Red for warning
                # Show warning if not already shown
                if not toolbar_cache.get("context_warning_shown", False) and context_usage > 0:
                    toolbar_cache["context_warning_shown"] = True
            elif context_usage >= 0.6:  # Above 60%
                auto_compact_str = f"✓ {int(context_usage * 100)}%"
                auto_compact_color = "ansiyellow"  # Yellow for caution
            elif context_usage > 0:  # Show percentage if available
                auto_compact_str = f"✓ {int(context_usage * 100)}%"
                auto_compact_color = "ansigreen"
            else:
                auto_compact_str = "✓"
                auto_compact_color = "ansigreen"
        else:
            if context_usage >= 0.8:  # Warning even when disabled
                auto_compact_str = f"✗ {int(context_usage * 100)}%!"
                auto_compact_color = "ansired"
            else:
                auto_compact_str = "✗"
                auto_compact_color = "ansired"

        # Get memory status
        memory_enabled = os.getenv("KRYON_MEMORY", "false").lower() == "true"
        memory_str = "✓" if memory_enabled else "✗"
        memory_color = "ansigreen" if memory_enabled else "ansigray"

        # Get streaming status
        streaming_enabled = os.getenv("KRYON_STREAM", "false").lower() == "true"
        stream_str = "✓" if streaming_enabled else "✗"
        stream_color = "ansigreen" if streaming_enabled else "ansigray"

        # Operative per-phase turn cap (F166) — real budget in effect.
        phase_turns = _phase_turn_cap()

        # Get tracing status
        tracing_enabled = os.getenv("KRYON_TRACING", "false").lower() == "true"
        trace_str = "✓" if tracing_enabled else "✗"
        trace_color = "ansigreen" if tracing_enabled else "ansigray"

        # Get active tool progress indicator
        active_tool_str = ""
        try:
            from kryon.util.streaming import _ACTIVE_TOOL_PROGRESS

            if _ACTIVE_TOOL_PROGRESS:
                # Get the most recent progress state
                last_key = list(_ACTIVE_TOOL_PROGRESS.keys())[-1]
                ps = _ACTIVE_TOOL_PROGRESS[last_key]
                tool_label = ps.tool_name or "tool"
                if ps.percentage is not None:
                    active_tool_str = f" | <ansicyan>🔧 {tool_label} {ps.percentage:.0f}%</ansicyan>"
                elif ps.total_lines > 0:
                    active_tool_str = f" | <ansicyan>🔧 {tool_label} {ps.total_lines}L</ansicyan>"
        except Exception:
            pass

        # Get terminal width to decide on toolbar format
        terminal_width = get_terminal_width()

        # Cost-related fields ($Limit, $:) are intentionally REMOVED —
        # Kryon runs on local models (Ollama), so cost tracking is not
        # relevant. Replaced with cybersec runtime state via
        # _get_kryon_state_str().
        kryon_compact = _get_kryon_state_str(compact=True)
        kryon_full = _get_kryon_state_str(compact=False)
        kryon_compact_block = f"{kryon_compact} | " if kryon_compact else ""
        kryon_full_block = f"{kryon_full} | " if kryon_full else ""

        if terminal_width < 120:  # Compact mode
            model_name = real_model_name()
            if len(model_name) > 14:
                model_name = model_name[:13] + "…"

            toolbar_cache["html"] = HTML(
                f"<{active_env_color}>{active_env_icon}</{active_env_color}> "
                f"<ansigreen>{model_name}</ansigreen> | "
                f"{kryon_compact_block}"
                f"<{auto_compact_color}>AC:{auto_compact_str}</{auto_compact_color}> | "
                f"<{stream_color}>S:{stream_str}</{stream_color}>"
                f"{active_tool_str} | "
                f"<ansigray>{current_time}</ansigray>"
            )
        elif terminal_width < 160:  # Medium mode
            toolbar_cache["html"] = HTML(
                f"<{active_env_color}><b>ENV:</b> {active_env_icon} {active_env_name[:15]}</{active_env_color}> | "
                f"<ansiyellow><b>Model:</b></ansiyellow> <ansigreen>{real_model_name()}</ansigreen> | "
                f"{kryon_full_block}"
                f"<ansicyan><b>AutoC:</b></ansicyan> <{auto_compact_color}>{auto_compact_str}</{auto_compact_color}> | "
                f"<ansicyan><b>Mem:</b></ansicyan> <{memory_color}>{memory_str}</{memory_color}> | "
                f"<ansicyan><b>Stream:</b></ansicyan> <{stream_color}>{stream_str}</{stream_color}>"
                f"{active_tool_str} | "
                f"<ansigray>{current_time_with_tz}</ansigray>"
            )
        else:  # Full mode
            toolbar_cache["html"] = HTML(
                f"<{active_env_color}><b>ENV:</b> {active_env_icon} {active_env_name}</{active_env_color}> | "
                f"<ansiyellow><b>Model:</b></ansiyellow> <ansigreen>{real_model_name()}</ansigreen> | "
                f"{kryon_full_block}"
                f"<ansicyan><b>AutoCompact:</b></ansicyan> <{auto_compact_color}>{auto_compact_str}</{auto_compact_color}> | "
                f"<ansicyan><b>Memory:</b></ansicyan> <{memory_color}>{memory_str}</{memory_color}> | "
                f"<ansicyan><b>Stream:</b></ansicyan> <{stream_color}>{stream_str}</{stream_color}> | "
                f"<ansicyan><b>Trace:</b></ansicyan> <{trace_color}>{trace_str}</{trace_color}> | "
                f"<ansiyellow><b>Phase:</b></ansiyellow> <ansiblue>{phase_turns}</ansiblue>"
                f"{active_tool_str} | "
                f"<ansigray>{current_time_with_tz}</ansigray>"
            )
        toolbar_cache["last_update"] = datetime.datetime.now()
    except Exception:  # pylint: disable=broad-except
        # If there's an error, set a simple toolbar
        toolbar_cache["html"] = HTML(f"<ansigray>{datetime.datetime.now().strftime('%H:%M')}</ansigray>")
        toolbar_cache["last_update"] = datetime.datetime.now()
    finally:
        _update_lock.release()


def _heartbeat_eye() -> str:
    """Markup for the live Ghost eye — idle breathe, or reacting to findings."""
    try:
        from kryon.repl.ui.ghost_state import eye_pt_markup

        return eye_pt_markup()
    except Exception:  # pragma: no cover
        return '<style fg="#45e0ef"><b>◆</b></style>'


def _toolbar_ghost_enabled() -> bool:
    """Mini-Ghost emblem in the toolbar (default on; disable with
    KRYON_TOOLBAR_GHOST=0). Skipped on narrow terminals to save space."""
    if os.getenv("KRYON_TOOLBAR_GHOST", "").strip().lower() in ("0", "false", "no", "off"):
        return False
    return get_terminal_width() >= 70


def _mini_ghost_block(body: str) -> str:
    """A 3-line compact Ghost with a live/reactive eye, the info `body` sitting
    on the middle row:

         ▲
        ◀◉▶  <info fields…>
         ▼
    """
    steel = "#2f6ea6"
    try:
        from kryon.repl.ui.ghost_state import eye_style, fresh_reaction

        glyph, color = eye_style()
        center = glyph if fresh_reaction() else "◉"
        eye = f'<style fg="{color}"><b>{center}</b></style>'
    except Exception:  # pragma: no cover
        eye = '<style fg="#45e0ef"><b>◉</b></style>'
    top = f' <style fg="{steel}">▲</style>'
    mid = f'<style fg="{steel}">◀</style>{eye}<style fg="{steel}">▶</style>  {body}'
    bot = f' <style fg="{steel}">▼</style>'
    return f"{top}\n{mid}\n{bot}"


def get_bottom_toolbar():
    """Get the bottom toolbar with system information (cached).

    The cached markup carries an «EYE» placeholder; we swap it for a
    time-based pulsing ◆ on every call so the toolbar breathes (the prompt's
    refresh_interval drives the ticks).
    """
    # If the toolbar is empty, initialize it
    if not toolbar_cache["html"]:
        # Create a simple initial toolbar while the full one loads
        current_time = datetime.datetime.now().strftime("%H:%M")
        timezone_name = datetime.datetime.now().astimezone().tzname()
        toolbar_cache["html"] = HTML(
            f"<ansigray>Loading system information... {current_time} {timezone_name}</ansigray>"
        )
        # Start background update
        threading.Thread(target=update_toolbar_in_background, daemon=True).start()

    html_obj = toolbar_cache["html"]
    body = getattr(html_obj, "value", None)
    if not body:
        return html_obj

    # Runs on EVERY prompt refresh tick (~2x/sec) — must never raise into
    # prompt_toolkit's redraw loop (an unescaped char in a docker image / model
    # name reaching the markup would make HTML() throw and spam tracebacks).
    # Fail soft to the cached object.
    try:
        # Mini-Ghost mode: the emblem's ◉ is the live eye, so drop the inline
        # «EYE» diamond from the Skills label and frame the info in the emblem.
        if _toolbar_ghost_enabled():
            clean = body.replace("«EYE» ", "").replace("«EYE»", "")
            return HTML(_mini_ghost_block(clean))

        # Single-line mode: pulse the «EYE» in place.
        if "«EYE»" in body:
            return HTML(body.replace("«EYE»", _heartbeat_eye()))
    except Exception:  # pragma: no cover — render path must not crash the prompt
        return html_obj
    return html_obj


def get_toolbar_with_refresh():
    """Get toolbar with refresh control."""
    now = datetime.datetime.now()
    seconds_elapsed = (now - toolbar_cache["last_update"]).total_seconds()

    # Check if we need to refresh the toolbar
    if seconds_elapsed >= toolbar_cache["refresh_interval"]:
        # Mark now (not at rebuild end) so ticks during a slow rebuild don't
        # re-trigger; the _update_lock is the hard backstop against pileup.
        toolbar_cache["last_update"] = now
        threading.Thread(target=update_toolbar_in_background, daemon=True).start()

    # Always return the cached version immediately
    return get_bottom_toolbar()


def set_context_usage(usage_percentage: float):
    """Set the current context usage percentage (called from openai_chatcompletions.py).

    C5: the rebuild-thread pileup that made `toolbar_cache` writes race is fixed
    by `_update_lock` (C1) — only one rebuild writes at a time. The remaining
    cross-thread touch is this single-bool `context_warning_shown` reset; a bool
    write is GIL-atomic so the worst case is a one-frame flap of the warning, not
    corruption. We deliberately do NOT take `_update_lock` here: it's held for
    the whole rebuild (up to ~10s on a slow `docker inspect`), and this runs on
    the model call path — blocking it would stall the LLM turn.
    """
    os.environ["KRYON_CONTEXT_USAGE"] = str(usage_percentage)
    # Reset warning flag if usage drops below threshold
    if usage_percentage < 0.8:
        toolbar_cache["context_warning_shown"] = False


# Initialize the toolbar on module import
threading.Thread(target=update_toolbar_in_background, daemon=True).start()


def get_container_info(container_id):
    """
    Retrieves information about a Docker container by its ID.

    Args:
        container_id (str): The ID of the Docker container.

    Returns:
        tuple: A tuple containing:
            - container_name (str): The image name (with "(stopped)" suffix if not running).
            - icon (str): An emoji representing the container type or status.
            - color (str): A string representing the display color (e.g., for UI rendering).
    """
    try:
        # Get the container's image name. timeout= so a wedged docker daemon can't
        # stall the status bar on every REPL refresh (these run constantly).
        image = subprocess.run(
            ["docker", "inspect", "--format", "{{.Config.Image}}", container_id],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()

        # Determine the appropriate icon and color based on the image type.
        icon = "🐳"
        color = "ansigreen"

        if "kali" in image.lower() or "parrot" in image.lower():
            icon = "🔒"
        elif "kryon" in image.lower():
            icon = "⭐"

        # Check whether the container is currently running.
        running = subprocess.run(
            ["docker", "ps", "--filter", f"id={container_id}", "--format", "{{.Status}}"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()

        if not running:
            image += " (stopped)"
            color = "ansiyellow"

        return image, icon, color

    except Exception:
        return f"Container {container_id[:12]}", "🐳", "ansiyellow"
