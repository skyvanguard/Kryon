"""
Streaming UI utilities for KRYON.

This module provides functions for streaming tool execution output
and agent responses with Rich panels.
"""

import atexit
import json
import os
import re
import signal
import sys
import threading
import time
import uuid
from typing import Any


def _hide_cost() -> bool:
    """Cost counters add noise when running on local Ollama (cost = 0).
    Default: hidden. Set `KRYON_HIDE_COST=0` to show them again
    (relevant if you ever route through a paid API)."""
    val = os.environ.get("KRYON_HIDE_COST", "1").strip().lower()
    return val in ("1", "true", "yes", "on")


def _dedup_render_check(stage: str, call_id: str | None) -> bool:
    """F77.D / Fase 11 — returns True if (stage, call_id) was ALREADY
    rendered, so the caller should skip emitting console output again.

    The SDK adapter's `items_to_messages()` walks the entire item history
    every turn to rebuild the API payload, which re-fires the render
    hooks for every previously-seen tool call. Without dedup, a tool from
    turn 1 prints (1 + remaining_turns) times.

    Stage is "invocation" (▸ tool args) or "completion" (✓ Ns · summary).
    Call_id is the model-supplied unique id for that tool invocation
    (e.g. "call_ga118jr7"). Returns False (and marks rendered) if call_id
    is None — empty call_id can't be deduped, so we err toward showing it
    once rather than swallowing it.
    """
    if not call_id:
        return False
    if not hasattr(_dedup_render_check, "_seen"):
        _dedup_render_check._seen = set()
    key = f"{stage}:{call_id}"
    if key in _dedup_render_check._seen:
        return True
    _dedup_render_check._seen.add(key)
    return False


def _reset_render_dedup() -> None:
    """Reset the cross-stage render dedup set. Wired to REPL turn boundaries
    so a fresh user prompt starts with a clean slate (and to keep the
    long-lived REPL session from accumulating call_ids forever).
    """
    if hasattr(_dedup_render_check, "_seen"):
        _dedup_render_check._seen.clear()


from rich.box import ROUNDED
from rich.console import Console, Group
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from rich.theme import Theme

from kryon.util.cost_tracker import (
    COST_TRACKER,
    calculate_model_cost,
    format_time,
    get_model_input_tokens,
    get_model_name,
)
from kryon.util.timing import start_idle_timer, stop_active_timer

# Set up theme for console
theme = Theme(
    {
        "timestamp": "#00BCD4",
        "agent": "#4CAF50",
        "arrow": "#FFFFFF",
        "content": "#ECEFF1",
        "tool": "#F44336",
        "cost": "#009688",
        "args_str": "#FFC107",
        "border": "#2196F3",
        "border_state": "#FFD700",
        "model": "#673AB7",
        "dim": "#9E9E9E",
        "current_token_count": "#E0E0E0",
        "total_token_count": "#757575",
        "context_tokens": "#0A0A0A",
        "success": "#4CAF50",
        "warning": "#FF9800",
        "error": "#F44336",
    }
)

console = Console(theme=theme)

# Set up a global tracker for live streaming panels
_LIVE_STREAMING_PANELS: dict[str, Any] = {}

# Global lock for coordinating parallel panel updates
_PANEL_UPDATE_LOCK = threading.Lock()

# Active tool progress states (call_id -> ProgressState), used by toolbar
_ACTIVE_TOOL_PROGRESS: dict[str, Any] = {}

# Track parallel execution state
_PARALLEL_EXECUTION_STATE = {
    "active": False,
    "panel_groups": {},  # Group panels by execution batch
    "current_batch_id": None,
}

# Global flag to track if cleanup is in progress
_cleanup_in_progress = False
_cleanup_lock = threading.Lock()


def cleanup_all_streaming_resources():
    """
    Clean up all active streaming resources.
    This is called when the program is interrupted or exits.
    """
    global _cleanup_in_progress

    with _cleanup_lock:
        if _cleanup_in_progress:
            return
        _cleanup_in_progress = True

    try:
        # Import here to avoid circular imports
        from kryon.util.thinking import cleanup_thinking_panels

        # Clean up all active Live streaming panels
        for _call_id, live in list(_LIVE_STREAMING_PANELS.items()):
            try:
                if hasattr(live, "stop"):
                    live.stop()
            except Exception:
                pass
        _LIVE_STREAMING_PANELS.clear()

        # Clean up all Claude thinking panels
        cleanup_thinking_panels()

        # Clean up active streaming contexts from create_agent_streaming_context
        if hasattr(create_agent_streaming_context, "_active_streaming"):
            for _context_key, context in list(create_agent_streaming_context._active_streaming.items()):
                try:
                    if context and context.get("live") and context.get("is_started"):
                        context["live"].stop()
                except Exception:
                    pass
            create_agent_streaming_context._active_streaming.clear()

        # Reset any streaming session states
        if hasattr(cli_print_tool_output, "_streaming_sessions"):
            cli_print_tool_output._streaming_sessions.clear()

        # Clean up parallel execute_code tracking
        if hasattr(start_tool_streaming, "_parallel_execute_code_agents"):
            start_tool_streaming._parallel_execute_code_agents.clear()

        # Clean up recent commands tracking
        if hasattr(start_tool_streaming, "_recent_commands"):
            start_tool_streaming._recent_commands.clear()

        # Reset parallel execution state
        global _PARALLEL_EXECUTION_STATE
        _PARALLEL_EXECUTION_STATE = {"active": False, "panel_groups": {}, "current_batch_id": None}

    except Exception as e:
        print(f"\nError during streaming cleanup: {e}", file=sys.stderr)
    finally:
        _cleanup_in_progress = False


def cleanup_agent_streaming_resources(agent_name):
    """
    Clean up streaming resources for a specific agent.

    Args:
        agent_name: Name of the agent whose streaming resources to clean up
    """
    if not hasattr(cli_print_tool_output, "_streaming_sessions"):
        return

    # Find and finish streaming sessions belonging to this agent
    sessions_to_cleanup = []
    for session_id, session_info in list(cli_print_tool_output._streaming_sessions.items()):
        # Check if this session belongs to the agent and is not complete
        if session_info.get("agent_name") == agent_name and not session_info.get("is_complete", False):
            sessions_to_cleanup.append((session_id, session_info))

    # Also clean up any Live panels for this agent
    global _LIVE_STREAMING_PANELS
    panels_to_cleanup = []
    for panel_id, panel_info in list(_LIVE_STREAMING_PANELS.items()):
        # Check if this is a static panel with matching agent
        if isinstance(panel_info, dict) and panel_info.get("type") == "static":
            # We don't store agent name in panel info, so we can't filter by agent
            # But we can clean up based on session completion
            if panel_id in [s[0] for s in sessions_to_cleanup]:
                panels_to_cleanup.append(panel_id)

    # Clean up panels first
    for panel_id in panels_to_cleanup:
        del _LIVE_STREAMING_PANELS[panel_id]

    # Clean up parallel execute_code agent tracking
    if hasattr(start_tool_streaming, "_parallel_execute_code_agents"):
        if agent_name in start_tool_streaming._parallel_execute_code_agents:
            start_tool_streaming._parallel_execute_code_agents.remove(agent_name)

    # Finish each session properly
    for session_id, session_info in sessions_to_cleanup:
        finish_tool_streaming(
            tool_name=session_info.get("tool_name", "unknown"),
            args=session_info.get("args", {}),
            output=session_info.get("current_output", "Execution completed"),
            call_id=session_id,
            execution_info={"status": "completed", "is_final": True},
            token_info={"agent_name": agent_name},  # Pass agent name for proper display
        )


def signal_handler(signum, frame):
    """
    Handle interrupt signals (CTRL+C) gracefully.
    """
    # Stop any active timers
    try:
        stop_active_timer()
        start_idle_timer()
    except Exception:
        pass

    # Clean up all streaming resources
    cleanup_all_streaming_resources()

    # Re-raise KeyboardInterrupt to allow normal interrupt handling
    raise KeyboardInterrupt()


# Register signal handler for CTRL+C
signal.signal(signal.SIGINT, signal_handler)

# Register cleanup at exit
atexit.register(cleanup_all_streaming_resources)


def get_language_from_code_block(lang_identifier):
    """
    Maps a language identifier from a markdown code block to a proper syntax
    highlighting language name. Handles common aliases and defaults.
    """
    # Convert to lowercase and strip whitespace
    lang = lang_identifier.lower().strip() if lang_identifier else ""

    # Map common language aliases to their proper names
    lang_map = {
        "": "text",
        "py": "python",
        "python3": "python",
        "js": "javascript",
        "jsx": "jsx",
        "ts": "typescript",
        "tsx": "tsx",
        "typescript": "typescript",
        "sh": "bash",
        "shell": "bash",
        "console": "bash",
        "terminal": "bash",
        "html": "html",
        "css": "css",
        "json": "json",
        "xml": "xml",
        "yml": "yaml",
        "yaml": "yaml",
        "c": "c",
        "cpp": "cpp",
        "c++": "cpp",
        "csharp": "csharp",
        "cs": "csharp",
        "java": "java",
        "go": "go",
        "golang": "go",
        "ruby": "ruby",
        "rb": "ruby",
        "rust": "rust",
        "php": "php",
        "sql": "sql",
        "diff": "diff",
        "markdown": "markdown",
        "md": "markdown",
        "text": "text",
        "plaintext": "text",
        "txt": "text",
    }

    return lang_map.get(lang, lang or "text")


def _format_tool_args(args, tool_name=None):
    """Format tool arguments as a clean string."""
    # If the tool is execute_code, we don't want to show any args in the main header
    if tool_name == "execute_code":
        return ""

    if isinstance(args, str):
        if args.strip().startswith("{") and args.strip().endswith("}"):
            try:
                parsed_dict = json.loads(args)
                return _format_tool_args(parsed_dict, tool_name=tool_name)
            except json.JSONDecodeError:
                return args
        else:
            return args

    if isinstance(args, dict):
        arg_parts = []
        for key, value in args.items():
            if value == "" or value == {} or value is None:
                continue
            if key in ["async_mode", "streaming"] and not value:
                continue

            value_str = str(value)
            if isinstance(value, str):
                if len(value_str) > 70 and key not in ["code", "args"]:
                    value_str = value_str[:67] + "..."
                arg_parts.append(f"{key}={value_str}")
            else:
                arg_parts.append(f"{key}={value_str}")
        return ", ".join(arg_parts)
    else:
        return str(args)


def _get_timing_info(execution_info=None):
    """Get timing information for display."""
    try:
        from kryon.cli import START_TIME

        total_time = time.time() - START_TIME if START_TIME else None
    except ImportError:
        total_time = None

    tool_time = None
    if execution_info:
        tool_time = execution_info.get("tool_time")

    timing_info = []
    if total_time:
        timing_info.append(f"Total: {format_time(total_time)}")
    if tool_time:
        timing_info.append(f"Tool: {format_time(tool_time)}")

    return timing_info, tool_time


def _create_token_display(
    interaction_input_tokens,
    interaction_output_tokens,
    interaction_reasoning_tokens,
    total_input_tokens,
    total_output_tokens,
    total_reasoning_tokens,
    model,
    interaction_cost=None,
    total_cost=None,
) -> Text:
    """Create token display text for agent messages."""
    model_name = get_model_name(model)

    if interaction_cost is not None:
        current_cost = float(interaction_cost)
    else:
        current_cost = COST_TRACKER.last_interaction_cost

    if total_cost is not None:
        total_cost_value = float(total_cost)
    else:
        total_cost_value = COST_TRACKER.last_total_cost

    # F77.D / Fase 5: compact footer (mirrors message_utils._create_token_display).
    tokens_text = Text(justify="left")
    show_cost = not _hide_cost()

    tokens_text.append(
        f"I:{interaction_input_tokens} O:{interaction_output_tokens}",
        style="dim cyan",
    )
    if interaction_reasoning_tokens > 0:
        tokens_text.append(f" R:{interaction_reasoning_tokens}", style="dim cyan")
    if show_cost and current_cost > 0:
        tokens_text.append(f" (${current_cost:.4f})", style="dim")

    context_pct = interaction_input_tokens / get_model_input_tokens(model_name) * 100
    if context_pct < 50:
        indicator = "OK"
        color_local = "green"
    elif context_pct < 80:
        indicator = "!!"
        color_local = "yellow"
    else:
        indicator = "XX"
        color_local = "red"

    tokens_text.append(" · ", style="dim")
    tokens_text.append(f"ctx {context_pct:.0f}%", style="dim cyan")
    tokens_text.append(" ", style="dim")
    tokens_text.append(indicator, style=color_local)

    return tokens_text


def _create_token_info_display(token_info=None):
    """Create token information display text."""
    if not token_info:
        return None

    model = token_info.get("model", "")
    interaction_input_tokens = token_info.get("interaction_input_tokens", 0)
    interaction_output_tokens = token_info.get("interaction_output_tokens", 0)
    interaction_reasoning_tokens = token_info.get("interaction_reasoning_tokens", 0)
    total_input_tokens = token_info.get("total_input_tokens", 0)
    total_output_tokens = token_info.get("total_output_tokens", 0)
    total_reasoning_tokens = token_info.get("total_reasoning_tokens", 0)

    if not (interaction_input_tokens > 0 or total_input_tokens > 0):
        return None

    return _create_token_display(
        interaction_input_tokens,
        interaction_output_tokens,
        interaction_reasoning_tokens,
        total_input_tokens,
        total_output_tokens,
        total_reasoning_tokens,
        model,
        token_info.get("interaction_cost"),
        token_info.get("total_cost"),
    )


def _print_simple_tool_output(tool_name, args, output, execution_info=None, token_info=None):
    """Print tool output without Rich formatting."""
    from wasabi import color

    _format_tool_args(args)

    if execution_info:
        time_taken = execution_info.get("time_taken", 0) or execution_info.get("tool_time", 0)
        if time_taken:
            pass

    timing_info, _ = _get_timing_info(execution_info)

    if token_info:
        model = token_info.get("model", "")
        interaction_input_tokens = token_info.get("interaction_input_tokens", 0)
        interaction_output_tokens = token_info.get("interaction_output_tokens", 0)
        interaction_reasoning_tokens = token_info.get("interaction_reasoning_tokens", 0)
        total_input_tokens = token_info.get("total_input_tokens", 0)
        total_output_tokens = token_info.get("total_output_tokens", 0)
        total_reasoning_tokens = token_info.get("total_reasoning_tokens", 0)

        if interaction_input_tokens > 0 or total_input_tokens > 0:
            print(
                color(
                    f"  Current: I:{interaction_input_tokens} O:{interaction_output_tokens} "
                    f"R:{interaction_reasoning_tokens}",
                    fg="cyan",
                )
            )

            if not _hide_cost():
                current_cost = COST_TRACKER.process_interaction_cost(
                    model,
                    interaction_input_tokens,
                    interaction_output_tokens,
                    interaction_reasoning_tokens,
                    token_info.get("interaction_cost"),
                )
                total_cost_value = COST_TRACKER.process_total_cost(
                    model,
                    total_input_tokens,
                    total_output_tokens,
                    total_reasoning_tokens,
                    token_info.get("total_cost"),
                )
                session_cost = COST_TRACKER.session_total_cost
                print(
                    color(
                        f"  Cost: Current ${current_cost:.4f} | Total ${total_cost_value:.4f} "
                        f"| Session ${session_cost:.4f}",
                        fg="cyan",
                    )
                )

            context_pct = interaction_input_tokens / get_model_input_tokens(model) * 100
            if context_pct < 50:
                indicator = "OK"
            elif context_pct < 80:
                indicator = "!!"
            else:
                indicator = "XX"
            print(color(f"  Context: {context_pct:.1f}% {indicator}", fg="cyan"))

    if output and len(str(output)) > 10000:
        output_str = str(output)
        first_part = output_str[:5000]
        last_part = output_str[-5000:]
        output = f"{first_part}\n\n... TRUNCATED ...\n\n{last_part}"

    print(output)
    print()


def _create_tool_panel_content(
    tool_name,
    args,
    output,
    execution_info=None,
    token_info=None,
    progress_state=None,
):
    """Create the header and content for a tool output panel."""
    is_running = execution_info and execution_info.get("status") == "running"

    # Truncate output during streaming to last 30 lines
    if is_running and output:
        lines = str(output).splitlines()
        if len(lines) > 30:
            output = f"... {len(lines) - 30} lines above ...\n" + "\n".join(lines[-30:])
    elif output and len(str(output)) > 10000:
        output_str = str(output)
        first_part = output_str[:5000]
        last_part = output_str[-5000:]
        output = f"{first_part}\n\n... TRUNCATED ...\n\n{last_part}"

    is_handoff = tool_name.startswith("transfer_to_")

    agent_name = None
    if token_info and isinstance(token_info, dict):
        agent_name = token_info.get("agent_name", None)

    args_str = _format_tool_args(args, tool_name=tool_name)
    timing_info, tool_time = _get_timing_info(execution_info)

    header = Text()
    if is_handoff:
        agent_name = None
        if tool_name.startswith("transfer_to_"):
            agent_name_raw = tool_name[len("transfer_to_") :]
            agent_name = " ".join(word.capitalize() for word in agent_name_raw.split("_"))
            parts = agent_name.split()
            for i, part in enumerate(parts):
                if part.upper() == part and len(part) > 1:
                    parts[i] = part.upper()
            agent_name = " ".join(parts)

        header.append(tool_name, style="#00BCD4")
        if agent_name:
            header.append(" → ", style="bold yellow")
            header.append(agent_name, style="bold green")

        if args_str:
            header.append("(", style="yellow")
            header.append(args_str, style="yellow")
            header.append(")", style="yellow")
    else:
        header.append(tool_name, style="#00BCD4")
        header.append("(", style="yellow")
        header.append(args_str, style="yellow")
        header.append(")", style="yellow")

    if timing_info:
        header.append(f" [{' | '.join(timing_info)}]", style="cyan")

    if execution_info and execution_info.get("environment"):
        env = execution_info.get("environment")
        host = execution_info.get("host", "")
        if host:
            header.append(f" [{env}:{host}]", style="magenta")
        else:
            header.append(f" [{env}]", style="magenta")

    if execution_info:
        status = execution_info.get("status", None)
        if status == "completed":
            header.append(" [Completed]", style="green")
        elif status == "running":
            header.append(" [Running]", style="yellow")
        elif status == "error":
            header.append(" [Error]", style="red")
        elif status == "timeout":
            header.append(" [Timeout]", style="red")

    token_content = _create_token_info_display(token_info)
    group_content = [header]

    if tool_name == "execute_code" and isinstance(args, dict):
        command = args.get("command")
        code_from_code_key = args.get("code")
        language_from_lang_key = args.get("language", "python")
        args_str_payload = args.get("args")

        panel1_content_str = None
        panel1_language_name = "text"
        panel1_title = "Executed Command Details"
        panel1_border_style = "cyan"

        if command == "execute" and code_from_code_key:
            panel1_content_str = code_from_code_key
            panel1_language_name = language_from_lang_key
            panel1_title = f"Code ({language_from_lang_key})"
            panel1_border_style = "cyan"
        elif args_str_payload:
            panel1_content_str = args_str_payload
            inferred_lang_for_args = "text"

            if command and command.lower() == "cat" and ("<<" in args_str_payload or ">" in args_str_payload):
                match = re.search(r"(?:>|>>)\s*([\w\./-]+\.\w+)", args_str_payload)
                if match:
                    filename = match.group(1)
                    ext = filename.split(".")[-1] if "." in filename else ""
                    inferred_lang_for_args = get_language_from_code_block(ext)
                else:
                    inferred_lang_for_args = get_language_from_code_block("bash")
            elif re.match(r"^[\w\./-]+\.\w+$", args_str_payload.strip()):
                filename = args_str_payload.strip()
                ext = filename.split(".")[-1] if "." in filename else ""
                inferred_lang_for_args = get_language_from_code_block(ext)
            else:
                try:
                    json.loads(args_str_payload)
                    inferred_lang_for_args = "json"
                except json.JSONDecodeError:
                    if args_str_payload.strip().startswith("<") and args_str_payload.strip().endswith(">"):
                        inferred_lang_for_args = "xml"
                    elif command:
                        inferred_lang_for_args = get_language_from_code_block("bash")

            panel1_language_name = inferred_lang_for_args
            panel1_title = f"Code ({panel1_language_name})"
            panel1_border_style = "yellow"

        if panel1_content_str is not None:
            syntax_obj_panel1 = Syntax(
                panel1_content_str,
                panel1_language_name,
                theme="monokai",
                line_numbers=True,
                background_color="#272822",
                indent_guides=True,
                word_wrap=True,
            )
            actual_panel1 = Panel(
                syntax_obj_panel1,
                title=panel1_title,
                border_style=panel1_border_style,
                title_align="left",
                box=ROUNDED,
                padding=(0, 1),
            )
            group_content.extend([Text("\n"), actual_panel1])

        if output:
            output_lang_name = "text"
            try:
                json.loads(output)
                output_lang_name = "json"
            except json.JSONDecodeError:
                if output.strip().startswith("<") and output.strip().endswith(">") and "<?xml" in output.lower():
                    output_lang_name = "xml"

            output_syntax = Syntax(
                output,
                get_language_from_code_block(output_lang_name),
                theme="monokai",
                background_color="#272822",
                word_wrap=True,
            )

            output_panel_title = "Output"
            if command and panel1_content_str:
                output_panel_title = f"Output of '{command}'"

            output_panel = Panel(
                output_syntax,
                title=output_panel_title,
                border_style="cyan",
                title_align="left",
                box=ROUNDED,
                padding=(0, 1),
            )
            group_content.extend([Text("\n"), output_panel])

    elif "command" in tool_name.lower() or "shell" in tool_name.lower():
        try:
            output_syntax = Syntax(output, "bash", theme="monokai", background_color="#272822", word_wrap=True)
            output_panel = Panel(
                output_syntax,
                title="Command Output",
                border_style="cyan",
                title_align="left",
                box=ROUNDED,
                padding=(0, 1),
            )
            group_content.extend([Text("\n"), output_panel])
        except Exception:
            group_content.extend([Text("\n"), Text(output)])

    elif output and output.strip():
        output_lang_name = "text"
        try:
            json.loads(output)
            output_lang_name = "json"
        except json.JSONDecodeError:
            if output.strip().startswith("<") and output.strip().endswith(">"):
                output_lang_name = "xml"

        syntax_lang = get_language_from_code_block(output_lang_name)
        output_syntax = Syntax(
            output,
            syntax_lang,
            theme="monokai",
            background_color="#272822",
            word_wrap=True,
            line_numbers=True,
            indent_guides=True,
        )

        output_display_panel = Panel(
            output_syntax,
            title="Tool Output",
            border_style="cyan",
            title_align="left",
            box=ROUNDED,
            padding=(0, 1),
        )
        group_content.extend([Text("\n"), output_display_panel])

    # Add progress bar if available
    if progress_state is not None:
        from kryon.repl.ui.progress import format_progress_bar

        progress_text = Text()
        progress_text.append(format_progress_bar(progress_state), style="cyan")
        group_content.extend([Text("\n"), progress_text])

    if token_content:
        group_content.extend([Text("\n"), token_content])

    return header, Group(*group_content)


def cli_print_tool_output(
    tool_name="",
    args="",
    output="",
    call_id=None,
    execution_info=None,
    token_info=None,
    streaming=False,
    progress_state=None,
):
    """
    Print a tool call output to the command line.

    Args:
        tool_name: Name of the tool
        args: Arguments passed to the tool
        output: The output of the tool
        call_id: Optional call ID for streaming updates
        execution_info: Optional execution information
        token_info: Optional token information
        streaming: Flag indicating if this is part of a streaming output
        progress_state: Optional ProgressState for progress bar rendering
    """
    if not output and not call_id and not streaming:
        return

    if tool_name and tool_name.startswith("_internal_"):
        return

    if token_info and isinstance(token_info, dict):
        agent_id = token_info.get("agent_id", "")
        if agent_id and agent_id.startswith("P") and agent_id[1:].isdigit():
            pass

    if tool_name == "cat_command" and isinstance(args, dict) and not streaming and "<< 'EOF'" in args.get("args", ""):
        return

    global _cleanup_in_progress
    if _cleanup_in_progress:
        return

    # F77.D / Fase 6: route non-execute_code finals through the flat renderer.
    # Streaming chunks and execute_code keep the legacy panel pipeline.
    # Fase 11: dedup by call_id — items_to_messages() in the SDK adapter
    # walks the full history every turn and re-fires this callback for
    # already-completed tools. Without dedup the same `✓ Ns · summary`
    # prints once per remaining turn (visible bug in screenshot).
    if not streaming and tool_name and tool_name != "execute_code" and output:
        if _dedup_render_check("completion", call_id):
            return
        try:
            _render_simple_tool_completion(
                tool_name,
                args,
                output,
                execution_info,
                token_info,
            )
            return
        except Exception:
            pass  # fall through to legacy renderer below

    if not hasattr(cli_print_tool_output, "_streaming_sessions"):
        cli_print_tool_output._streaming_sessions = {}

    if not hasattr(cli_print_tool_output, "_seen_calls"):
        cli_print_tool_output._seen_calls = {}

    if not hasattr(cli_print_tool_output, "_displayed_commands"):
        cli_print_tool_output._displayed_commands = set()
        cli_print_tool_output._last_cleanup = time.time()

    current_time = time.time()
    if current_time - cli_print_tool_output._last_cleanup > 300:
        cli_print_tool_output._displayed_commands.clear()
        cli_print_tool_output._last_cleanup = current_time

    agent_context = ""
    if token_info and isinstance(token_info, dict):
        agent_name = token_info.get("agent_name", "")
        agent_id = token_info.get("agent_id", "")
        interaction_counter = token_info.get("interaction_counter", 0)

        if agent_id and agent_id.startswith("P"):
            agent_context = f"agent_{agent_id}"
        elif agent_name:
            agent_context = f"agent_{agent_name.replace(' ', '_')}"

        if interaction_counter > 0:
            agent_context += f"_turn_{interaction_counter}"

    effective_command_args_str = ""
    if isinstance(args, dict):
        if "args" in args:
            effective_command_args_str = args.get("args", "")
        elif "command" in args:
            effective_command_args_str = args.get("command", "")
        elif "query" in args:
            effective_command_args_str = args.get("query", "")
        else:
            effective_command_args_str = json.dumps(args, sort_keys=True)

        if "command" in args and args.get("session_id"):
            effective_command_args_str = f"{args.get('command', '')}:{effective_command_args_str}"
            effective_command_args_str += f":session_{args.get('session_id', '')}"
    elif isinstance(args, str):
        try:
            parsed_json_args = json.loads(args)
            if isinstance(parsed_json_args, dict):
                if "args" in parsed_json_args:
                    effective_command_args_str = parsed_json_args.get("args", "")
                elif "command" in parsed_json_args:
                    effective_command_args_str = parsed_json_args.get("command", "")
                elif "query" in parsed_json_args:
                    effective_command_args_str = parsed_json_args.get("query", "")
                else:
                    effective_command_args_str = json.dumps(parsed_json_args, sort_keys=True)

                if "command" in parsed_json_args and parsed_json_args.get("session_id"):
                    effective_command_args_str = f"{parsed_json_args.get('command', '')}:{effective_command_args_str}"
                    effective_command_args_str += f":session_{parsed_json_args.get('session_id', '')}"
            else:
                effective_command_args_str = parsed_json_args if isinstance(parsed_json_args, str) else args
        except json.JSONDecodeError:
            effective_command_args_str = args

    if agent_context:
        command_key = f"{agent_context}:{tool_name}:{effective_command_args_str}"
    else:
        command_key = f"{tool_name}:{effective_command_args_str}"

    if isinstance(args, dict) and "call_counter" in args:
        call_counter = args["call_counter"]
        command_key += f":counter_{call_counter}"

    if isinstance(args, dict) and args.get("session_id") and args.get("input_to_session"):
        command_key += f":ts_{int(time.time() * 1000)}"

    if isinstance(args, dict) and args.get("auto_output"):
        command_key += ":auto_output"

    streaming_enabled = os.getenv("KRYON_STREAM", "false").lower() == "true"

    if streaming:
        if call_id:
            is_parallel = int(os.getenv("KRYON_PARALLEL", "1")) > 1

            if call_id not in cli_print_tool_output._streaming_sessions:
                cli_print_tool_output._streaming_sessions[call_id] = {
                    "tool_name": tool_name,
                    "args": args,
                    "buffer": output if output else "",
                    "start_time": time.time(),
                    "last_update": time.time(),
                    "command_key": command_key,
                    "is_complete": False,
                    "agent_name": token_info.get("agent_name") if token_info else None,
                    "current_output": output if output else "",
                }
                if command_key not in cli_print_tool_output._displayed_commands:
                    cli_print_tool_output._displayed_commands.add(command_key)

                if (
                    tool_name == "execute_code"
                    and not is_parallel
                    and isinstance(args, dict)
                    and "code" in args
                    and output == "Executing code..."
                ):
                    return
            else:
                session = cli_print_tool_output._streaming_sessions[call_id]
                session["buffer"] = output
                session["current_output"] = output
                session["last_update"] = time.time()
                if execution_info and execution_info.get("is_final", False):
                    session["is_complete"] = True

                if is_parallel and call_id in _LIVE_STREAMING_PANELS:
                    panel_info = _LIVE_STREAMING_PANELS[call_id]
                    if isinstance(panel_info, dict) and panel_info.get("type") == "static":
                        panel_info["last_output"] = output
                        panel_info["last_update"] = time.time()
                        return

            try:
                current_args_for_display = cli_print_tool_output._streaming_sessions[call_id]["args"]
                header, content = _create_tool_panel_content(
                    tool_name,
                    current_args_for_display,
                    cli_print_tool_output._streaming_sessions[call_id]["buffer"],
                    execution_info,
                    token_info,
                    progress_state=progress_state,
                )

                status = "running"
                if execution_info:
                    status = execution_info.get("status", "running")

                # F77.D / Fase 6: palette B — running uses cyan (was yellow).
                # Semantic colors preserved: green=ok, red=error.
                border_style = "cyan"
                if status == "completed":
                    border_style = "green"
                elif status in ["error", "timeout"]:
                    border_style = "red"

                agent_prefix = ""
                if token_info and token_info.get("agent_name"):
                    agent_prefix = f"[cyan]{token_info['agent_name']}[/cyan] - "

                if status == "running":
                    title = f"{agent_prefix}[bold cyan]Running[/bold cyan]"
                elif status == "completed":
                    title = f"{agent_prefix}[bold green]Completed[/bold green]"
                elif status == "error":
                    title = f"{agent_prefix}[bold red]Error[/bold red]"
                elif status == "timeout":
                    title = f"{agent_prefix}[bold red]Timeout[/bold red]"
                else:
                    title = f"{agent_prefix}[bold blue]Tool Execution[/bold blue]"

                panel = Panel(
                    content,
                    title=title,
                    border_style=border_style,
                    padding=(0, 1),
                    box=ROUNDED,
                    title_align="left",
                )

                is_parallel = int(os.getenv("KRYON_PARALLEL", "1")) > 1
                is_container = bool(os.getenv("KRYON_ACTIVE_CONTAINER", ""))

                if call_id in _LIVE_STREAMING_PANELS:
                    with _PANEL_UPDATE_LOCK:
                        panel_info = _LIVE_STREAMING_PANELS[call_id]

                        if isinstance(panel_info, dict) and panel_info.get("type") == "static":
                            panel_info["last_output"] = output
                            panel_info["last_update"] = time.time()
                            panel_info["updates_suppressed"] = panel_info.get("updates_suppressed", 0) + 1

                            if execution_info and execution_info.get("is_final", False):
                                panel_info["final_shown"] = True
                                panel_info["is_complete"] = True
                                if call_id in cli_print_tool_output._streaming_sessions:
                                    cli_print_tool_output._streaming_sessions[call_id]["is_complete"] = True
                            return
                        else:
                            try:
                                panel_info.update(panel)
                            except Exception:
                                try:
                                    panel_info.stop()
                                except Exception:
                                    pass
                                del _LIVE_STREAMING_PANELS[call_id]

                    if execution_info and execution_info.get("is_final", False):
                        with _PANEL_UPDATE_LOCK:
                            if call_id in _LIVE_STREAMING_PANELS:
                                panel_info = _LIVE_STREAMING_PANELS[call_id]
                                if isinstance(panel_info, dict) and panel_info.get("type") == "static":
                                    del _LIVE_STREAMING_PANELS[call_id]
                                    if call_id in cli_print_tool_output._streaming_sessions:
                                        cli_print_tool_output._streaming_sessions[call_id]["is_complete"] = True
                                    return
                                else:
                                    time.sleep(0.2)
                                    try:
                                        panel_info.stop()
                                    except Exception:
                                        pass
                                    del _LIVE_STREAMING_PANELS[call_id]
                else:
                    with _PANEL_UPDATE_LOCK:
                        is_parallel = int(os.getenv("KRYON_PARALLEL", "1")) > 1
                        is_container = bool(os.getenv("KRYON_ACTIVE_CONTAINER", ""))

                        if is_parallel:
                            if call_id not in _LIVE_STREAMING_PANELS:
                                if is_container and execution_info and execution_info.get("is_final", False):
                                    local_console = Console(theme=theme)
                                    local_console.print(panel)

                                    _LIVE_STREAMING_PANELS[call_id] = {
                                        "type": "static",
                                        "displayed": True,
                                        "last_update": time.time(),
                                        "last_output": output,
                                        "initial_output": output,
                                        "initial_panel_printed": True,
                                        "tool_name": tool_name,
                                        "command_key": command_key,
                                        "is_container": is_container,
                                        "final_shown": True,
                                        "is_complete": True,
                                    }
                                else:
                                    local_console = Console(theme=theme)
                                    local_console.print(panel)

                                    _LIVE_STREAMING_PANELS[call_id] = {
                                        "type": "static",
                                        "displayed": True,
                                        "last_update": time.time(),
                                        "last_output": output,
                                        "initial_output": output,
                                        "initial_panel_printed": True,
                                        "tool_name": tool_name,
                                        "command_key": command_key,
                                        "is_container": is_container,
                                        "final_shown": False,
                                    }
                        else:
                            local_console = Console(theme=theme)
                            live = Live(panel, console=local_console, refresh_per_second=4, auto_refresh=True)
                            try:
                                live.start()
                                _LIVE_STREAMING_PANELS[call_id] = live
                            except Exception:
                                _print_simple_tool_output(tool_name, args, output, execution_info, token_info)

                return

            except (ImportError, Exception):
                with _PANEL_UPDATE_LOCK:
                    if call_id in _LIVE_STREAMING_PANELS:
                        try:
                            _LIVE_STREAMING_PANELS[call_id].stop()
                        except Exception:
                            pass
                        del _LIVE_STREAMING_PANELS[call_id]

                _print_simple_tool_output(tool_name, args, output, execution_info, token_info)
                return

    is_first_display = False

    if not streaming:
        if not hasattr(cli_print_tool_output, "_command_display_times"):
            cli_print_tool_output._command_display_times = {}

        if command_key in cli_print_tool_output._displayed_commands:
            last_display = cli_print_tool_output._command_display_times.get(command_key, 0)
            current_time = time.time()

            if not streaming_enabled and current_time - last_display < 0.5:
                return

            if streaming_enabled:
                return

            if not output:
                return

        is_first_display = command_key not in cli_print_tool_output._displayed_commands
        cli_print_tool_output._displayed_commands.add(command_key)

    if call_id and not streaming:
        seen_call_key = f"{call_id}:{command_key}:{output[:20] if output else ''}"

        if seen_call_key in cli_print_tool_output._seen_calls:
            return

        cli_print_tool_output._seen_calls[seen_call_key] = True

    if tool_name == "execute_code" and call_id and not streaming:
        if (
            hasattr(cli_print_tool_output, "_streaming_sessions")
            and call_id in cli_print_tool_output._streaming_sessions
            and cli_print_tool_output._streaming_sessions[call_id].get("special_output_shown", False)
        ):
            return

    if tool_name == "execute_code" and not streaming and isinstance(args, dict):
        pass

    try:
        local_console = Console(theme=theme)

        display_args = args
        if isinstance(args, dict):
            display_args = {k: v for k, v in args.items() if k not in ["call_counter", "input_to_session"]}

        header, content = _create_tool_panel_content(
            tool_name,
            display_args,
            output,
            execution_info,
            token_info,
            progress_state=progress_state,
        )
        args_str = _format_tool_args(display_args, tool_name=tool_name)

        # F77.D / Fase 6: palette B — neutral default is cyan (was blue).
        border_style = "cyan"
        if execution_info:
            status = execution_info.get("status", "completed")
            if status == "completed":
                border_style = "green"
            elif status == "error":
                border_style = "red"
            elif status == "timeout":
                border_style = "red"

        is_handoff = tool_name.startswith("transfer_to_")

        agent_prefix = ""
        if token_info and token_info.get("agent_name"):
            agent_prefix = f"[cyan]{token_info['agent_name']}[/cyan] - "

        if is_handoff:
            agent_name = None
            if tool_name.startswith("transfer_to_"):
                agent_name_raw = tool_name[len("transfer_to_") :]
                agent_name = " ".join(word.capitalize() for word in agent_name_raw.split("_"))
                parts = agent_name.split()
                for i, part in enumerate(parts):
                    if part.upper() == part and len(part) > 1:
                        parts[i] = part.upper()
                agent_name = " ".join(parts)

            if execution_info:
                status = execution_info.get("status", "completed")
                if status == "completed":
                    title = f"{agent_prefix}[bold green]Handoff: {agent_name} [Completed][/bold green]"
                elif status == "error":
                    title = f"{agent_prefix}[bold red]Handoff: {agent_name} [Error][/bold red]"
                elif status == "timeout":
                    title = f"{agent_prefix}[bold red]Handoff: {agent_name} [Timeout][/bold red]"
                else:
                    title = f"{agent_prefix}[bold cyan]Handoff: {agent_name}[/bold cyan]"
            else:
                title = f"{agent_prefix}[bold cyan]Handoff: {agent_name}[/bold cyan]"
        else:
            if execution_info:
                status = execution_info.get("status", "completed")
                if status == "completed":
                    title = f"{agent_prefix}[bold green]{tool_name}({args_str}) [Completed][/bold green]"
                elif status == "error":
                    title = f"{agent_prefix}[bold red]{tool_name}({args_str}) [Error][/bold red]"
                elif status == "timeout":
                    title = f"{agent_prefix}[bold red]{tool_name}({args_str}) [Timeout][/bold red]"
                else:
                    title = f"{agent_prefix}[bold cyan]{tool_name}({args_str})[/bold cyan]"
            else:
                title = f"{agent_prefix}[bold cyan]{tool_name}({args_str})[/bold cyan]"

        panel = Panel(
            content,
            title=title,
            border_style=border_style,
            padding=(0, 1),
            box=ROUNDED,
            title_align="left",
        )

        if not streaming_enabled and not streaming and is_first_display:
            display_agent_name = ""
            if token_info and token_info.get("agent_name"):
                display_agent_name = token_info.get("agent_name")
            else:
                display_agent_name = "Agent"

            command_text = ""
            if isinstance(display_args, dict):
                if "command" in display_args:
                    command_text = display_args.get("command", "")
                    if "args" in display_args and display_args["args"]:
                        command_text += f" {display_args['args']}"
                elif "full_command" in display_args:
                    command_text = display_args.get("full_command", "")
                else:
                    command_text = str(display_args)
            else:
                command_text = str(display_args)

            command_panel = Panel(
                f"[bold cyan]{command_text}[/bold cyan]",
                title=f"[bold blue]{display_agent_name} - Executing Command[/bold blue]",
                border_style="cyan",
                padding=(0, 1),
                box=ROUNDED,
                title_align="left",
                width=None,
                expand=False,
            )

            local_console.print(command_panel)
            local_console.print()

        local_console.print(panel)

        if not streaming and command_key:
            cli_print_tool_output._command_display_times[command_key] = time.time()

    except (ImportError, Exception):
        _print_simple_tool_output(tool_name, args, output, execution_info, token_info)

        if not streaming and command_key:
            cli_print_tool_output._command_display_times[command_key] = time.time()


def create_agent_streaming_context(agent_name, counter, model):
    """
    Create a streaming context object that maintains state for streaming agent output.
    """
    import shutil
    from datetime import datetime

    if not hasattr(create_agent_streaming_context, "_active_streaming"):
        create_agent_streaming_context._active_streaming = {}

    context_key = f"{agent_name}_{counter}"
    if context_key in create_agent_streaming_context._active_streaming:
        return create_agent_streaming_context._active_streaming[context_key]

    try:
        timestamp = datetime.now().strftime("%H:%M:%S")
        terminal_width, _ = shutil.get_terminal_size((100, 24))
        panel_width = min(terminal_width - 4, 120)

        header = Text()
        header.append(f"[{counter}] ", style="bold cyan")
        header.append(f"Agent: {agent_name} ", style="bold green")
        header.append(">>\n", style="yellow")

        content = Text("")

        footer = Text()
        footer.append(f"\n[{timestamp}", style="dim")
        if model:
            footer.append(f" ({model})", style="bold magenta")
        footer.append("]", style="dim")

        # F77.D / Fase 4: agent narrative renders inline (no Panel envelope).
        panel = Text.assemble(header, content, footer)

        live = Live(
            panel,
            refresh_per_second=10,
            console=console,
            auto_refresh=True,
            vertical_overflow="visible",
        )

        context = {
            "live": live,
            "panel": panel,
            "header": header,
            "content": content,
            "footer": footer,
            "timestamp": timestamp,
            "model": model,
            "agent_name": agent_name,
            "panel_width": panel_width,
            "is_started": False,
            "error": None,
            "context_key": context_key,
        }

        create_agent_streaming_context._active_streaming[context_key] = context

        return context
    except Exception as e:
        print(f"Error creating streaming context: {e}", file=sys.stderr)
        return None


def update_agent_streaming_content(context, text_delta, token_stats=None):
    """Update the streaming content with new text."""
    if not context:
        return False

    global _cleanup_in_progress
    if _cleanup_in_progress:
        return False

    try:
        if text_delta:
            from kryon.util.message_utils import parse_message_content

            parsed_delta = parse_message_content(text_delta)

            if not parsed_delta or parsed_delta.strip() == "":
                if token_stats:
                    pass
            else:
                agent_name = context.get("agent_name", "")
                if (
                    agent_name
                    and hasattr(start_tool_streaming, "_parallel_execute_code_agents")
                    and agent_name in start_tool_streaming._parallel_execute_code_agents
                ):
                    if not hasattr(context, "_execute_code_noted"):
                        context["_execute_code_noted"] = True
                        context["content"].append("[Execute code output shown in panels above]\n")
                    if any(
                        marker in parsed_delta.lower() for marker in ["execute", "code", "output", "running", "```"]
                    ):
                        return True
                else:
                    context["content"].append(parsed_delta)
        elif not token_stats:
            return True

        if token_stats:
            footer_stats = Text()
            footer_stats.append(f"\n[{context['timestamp']}", style="dim")
            if context["model"]:
                footer_stats.append(f" ({context['model']})", style="bold magenta")
            footer_stats.append("]", style="dim")

            input_tokens = token_stats.get("input_tokens", 0)
            output_tokens = token_stats.get("output_tokens", 0)
            interaction_cost = token_stats.get("cost", 0.0)

            session_total_cost = token_stats.get("total_cost", 0.0)
            if session_total_cost == 0.0 and hasattr(COST_TRACKER, "session_total_cost"):
                session_total_cost = COST_TRACKER.session_total_cost

            if input_tokens > 0:
                footer_stats.append(" | ", style="dim")
                footer_stats.append(f"I:{input_tokens} O:{output_tokens}", style="green")

                if not _hide_cost():
                    if interaction_cost > 0:
                        footer_stats.append(f" (${interaction_cost:.4f})", style="bold cyan")
                    footer_stats.append(" | Session: ", style="dim")
                    footer_stats.append(f"${session_total_cost:.4f}", style="bold magenta")

                model_name = context.get("model", os.environ.get("KRYON_MODEL", "kryon-local"))
                context_pct = input_tokens / get_model_input_tokens(model_name) * 100
                if context_pct < 50:
                    indicator = "OK"
                    color_name = "green"
                elif context_pct < 80:
                    indicator = "!!"
                    color_name = "yellow"
                else:
                    indicator = "XX"
                    color_name = "red"
                footer_stats.append(f" {indicator} {context_pct:.1f}%", style=f"bold {color_name}")

            context["footer"] = footer_stats

        # F77.D / Fase 4: agent narrative renders inline (no Panel envelope).
        updated_panel = Text.assemble(context["header"], context["content"], context["footer"])

        if not context.get("is_started", False):
            try:
                context["live"].start()
                context["is_started"] = True
            except Exception as e:
                context["error"] = str(e)
                context_key = context.get("context_key")
                if context_key and hasattr(create_agent_streaming_context, "_active_streaming"):
                    create_agent_streaming_context._active_streaming.pop(context_key, None)
                return False

        if context.get("is_started", False):
            context["live"].update(updated_panel)
            context["panel"] = updated_panel
            context["live"].refresh()
        return True
    except Exception as e:
        context["error"] = str(e)
        context_key = context.get("context_key")
        if context_key and hasattr(create_agent_streaming_context, "_active_streaming"):
            create_agent_streaming_context._active_streaming.pop(context_key, None)
        return False


def finish_agent_streaming(context, final_stats=None):
    """Finish the streaming session and display final stats if available."""
    if not context:
        return False

    global _cleanup_in_progress
    if _cleanup_in_progress:
        return False

    context_key = context.get("context_key")
    if context_key and hasattr(create_agent_streaming_context, "_active_streaming"):
        create_agent_streaming_context._active_streaming.pop(context_key, None)

    try:
        if not context["content"] or context["content"].plain == "":
            if not context.get("is_started", False):
                return True
            try:
                context["live"].stop()
            except Exception:
                pass
            return True

        tokens_text = None
        if final_stats:
            interaction_input_tokens = final_stats.get("interaction_input_tokens")
            interaction_output_tokens = final_stats.get("interaction_output_tokens")
            interaction_reasoning_tokens = final_stats.get("interaction_reasoning_tokens")
            total_input_tokens = final_stats.get("total_input_tokens")
            total_output_tokens = final_stats.get("total_output_tokens")
            total_reasoning_tokens = final_stats.get("total_reasoning_tokens")

            interaction_cost = float(final_stats.get("interaction_cost", 0.0))
            total_cost = float(final_stats.get("total_cost", 0.0))

            model_name = context.get("model", "")
            if not isinstance(model_name, str):
                model_name = os.environ.get("KRYON_MODEL", "kryon-local")

            if (
                interaction_input_tokens is not None
                and interaction_output_tokens is not None
                and interaction_reasoning_tokens is not None
                and total_input_tokens is not None
                and total_output_tokens is not None
                and total_reasoning_tokens is not None
            ):
                if interaction_cost is None or interaction_cost == 0.0:
                    interaction_cost = calculate_model_cost(
                        model_name, interaction_input_tokens, interaction_output_tokens
                    )
                if total_cost is None or total_cost == 0.0:
                    total_cost = calculate_model_cost(model_name, total_input_tokens, total_output_tokens)

                tokens_text = _create_token_display(
                    interaction_input_tokens,
                    interaction_output_tokens,
                    interaction_reasoning_tokens,
                    total_input_tokens,
                    total_output_tokens,
                    total_reasoning_tokens,
                    model_name,
                    interaction_cost,
                    total_cost,
                )

                compact_tokens = Text()
                compact_tokens.append(" | ", style="dim")
                compact_tokens.append(f"I:{interaction_input_tokens} O:{interaction_output_tokens} ", style="green")

                if not _hide_cost():
                    compact_tokens.append(f"(${interaction_cost:.4f}) ", style="bold cyan")
                    session_total_cost = (
                        COST_TRACKER.session_total_cost if hasattr(COST_TRACKER, "session_total_cost") else total_cost
                    )
                    compact_tokens.append(" | Session: ", style="dim")
                    compact_tokens.append(f"${session_total_cost:.4f}", style="bold magenta")

                context_pct = interaction_input_tokens / get_model_input_tokens(model_name) * 100
                if context_pct < 50:
                    indicator = "OK"
                elif context_pct < 80:
                    indicator = "!!"
                else:
                    indicator = "XX"
                compact_tokens.append(f"{indicator} {context_pct:.1f}%", style="bold")

        if "footer" in context and final_stats:
            context["footer"] = Text()
            context["footer"].append(f"\n[{context['timestamp']}", style="dim")
            if context["model"]:
                context["footer"].append(f" ({context['model']})", style="bold magenta")
            context["footer"].append("]", style="dim")

            if final_stats and "compact_tokens" in locals():
                context["footer"].append(compact_tokens)

        # Render the accumulated streamed text as Markdown so headers, bold,
        # lists, tables and fenced code blocks look correct. Rich's Markdown
        # handles line wrapping, so run-together tokens still render readably.
        raw_text = context["content"].plain if context.get("content") else ""
        body: Any = Markdown(raw_text) if raw_text.strip() else Text("")

        # F77.D / Fase 4: agent narrative renders inline (no Panel envelope).
        final_panel = Group(
            context["header"],
            body,
            tokens_text if tokens_text else Text(""),
            context["footer"],
        )

        if context.get("is_started", False):
            try:
                context["live"].update(final_panel)
                time.sleep(0.1)
                context["live"].stop()
            except Exception as e:
                context["error"] = str(e)
                try:
                    context["live"].stop()
                except Exception:
                    pass

        return True
    except Exception as e:
        if not context.get("error"):
            context["error"] = str(e)

        try:
            if context.get("is_started", False) and context.get("live"):
                context["live"].stop()
        except Exception:
            pass

        return False


def start_tool_streaming(tool_name, args, call_id=None, token_info=None):
    """Start a streaming tool execution session."""
    if tool_name and tool_name.startswith("_internal_"):
        return f"internal_{str(uuid.uuid4())[:8]}"

    if tool_name == "_internal_file_creation":
        return f"file_create_{str(uuid.uuid4())[:8]}"

    is_parallel = False
    if token_info and isinstance(token_info, dict):
        agent_id = token_info.get("agent_id", "")
        if agent_id and agent_id.startswith("P") and agent_id[1:].isdigit():
            is_parallel = True

    if tool_name == "execute_code" and is_parallel and isinstance(args, dict) and "code" in args:
        if not call_id:
            call_id = f"exec_{str(uuid.uuid4())[:8]}"

        if token_info and isinstance(token_info, dict):
            agent_name = token_info.get("agent_name", "")
            if agent_name:
                if not hasattr(start_tool_streaming, "_parallel_execute_code_agents"):
                    start_tool_streaming._parallel_execute_code_agents = set()
                start_tool_streaming._parallel_execute_code_agents.add(agent_name)

        local_console = Console()

        agent_name = token_info.get("agent_name", "Agent") if token_info else "Agent"
        code = args.get("code", "")
        language = args.get("language", "python")
        filename = args.get("filename", "exploit")

        extensions = {
            "python": "py",
            "php": "php",
            "bash": "sh",
            "shell": "sh",
            "ruby": "rb",
            "perl": "pl",
            "golang": "go",
            "go": "go",
            "javascript": "js",
            "js": "js",
            "typescript": "ts",
            "ts": "ts",
            "rust": "rs",
            "csharp": "cs",
            "cs": "cs",
            "java": "java",
            "kotlin": "kt",
            "c": "c",
            "cpp": "cpp",
            "c++": "cpp",
        }
        ext = extensions.get(language, "txt")

        workspace = args.get("workspace", "")
        environment = args.get("environment", "")

        if environment == "Container" and workspace:
            full_path = f"{workspace}/{filename}.{ext}"
        elif workspace:
            cwd = os.getcwd()
            if workspace == os.path.basename(cwd):
                full_path = os.path.join(cwd, f"{filename}.{ext}")
            else:
                full_path = f"{workspace}/{filename}.{ext}"
        else:
            full_path = os.path.join(os.getcwd(), f"{filename}.{ext}")

        code_syntax = Syntax(
            code,
            language,
            theme="monokai",
            line_numbers=True,
            background_color="#272822",
            indent_guides=True,
            word_wrap=True,
        )
        code_panel = Panel(
            code_syntax,
            title=f"[bold cyan]{agent_name}[/bold cyan] - Code saved to: [yellow]{full_path}[/yellow]",
            border_style="cyan",
            title_align="left",
            box=ROUNDED,
            padding=(0, 1),
        )

        local_console.print(code_panel)

        if not hasattr(cli_print_tool_output, "_streaming_sessions"):
            cli_print_tool_output._streaming_sessions = {}
        if call_id not in cli_print_tool_output._streaming_sessions:
            cli_print_tool_output._streaming_sessions[call_id] = {}
        cli_print_tool_output._streaming_sessions[call_id]["code_panel_shown"] = True

        return call_id

    agent_context = ""
    if token_info and isinstance(token_info, dict):
        agent_name = token_info.get("agent_name", "")
        agent_id = token_info.get("agent_id", "")
        interaction_counter = token_info.get("interaction_counter", 0)

        if agent_id and agent_id.startswith("P"):
            agent_context = f"agent_{agent_id}"
        elif agent_name:
            agent_context = f"agent_{agent_name.replace(' ', '_')}"

        if interaction_counter > 0:
            agent_context += f"_turn_{interaction_counter}"

    if isinstance(args, dict):
        cmd_args = args.get("args", "")
        effective_args = cmd_args
    else:
        effective_args = str(args)

    if agent_context:
        command_key = f"{agent_context}:{tool_name}:{effective_args}"
    else:
        command_key = f"{tool_name}:{effective_args}"

    if not hasattr(start_tool_streaming, "_recent_commands"):
        start_tool_streaming._recent_commands = {}

    for existing_call_id, info in list(start_tool_streaming._recent_commands.items()):
        timestamp = info.get("timestamp", 0)
        if time.time() - timestamp < 10.0:
            existing_command_key = info.get("command_key", "")
            if (
                hasattr(cli_print_tool_output, "_streaming_sessions")
                and existing_call_id in cli_print_tool_output._streaming_sessions
            ):
                session = cli_print_tool_output._streaming_sessions[existing_call_id]
                if existing_command_key == command_key and not session.get("is_complete", False):
                    return existing_call_id

    if not call_id:
        cmd_part = ""
        if isinstance(args, dict) and "command" in args:
            cmd_part = f"{args['command']}_"
        call_id = f"cmd_{cmd_part}{str(uuid.uuid4())[:8]}"

    start_tool_streaming._recent_commands[call_id] = {
        "timestamp": time.time(),
        "command_key": command_key,
    }

    current_time = time.time()
    start_tool_streaming._recent_commands = {
        k: v for k, v in start_tool_streaming._recent_commands.items() if current_time - v.get("timestamp", 0) < 30
    }

    # NEW PATH (Fase 3): non-code tools render their invocation as a
    # single line via the palette-B renderer. execute_code keeps the
    # syntax-highlighted code panel below — that's a value-add.
    if tool_name and tool_name != "execute_code":
        try:
            from kryon.repl.ui.tool_call_renderer import (
                render_tool_invocation,
                summarize_args,
            )

            local_console = Console()
            args_summary = summarize_args(tool_name, args)
            render_tool_invocation(
                tool_name=tool_name,
                args_summary=args_summary,
                console=local_console,
            )
            # No early return — let the rest of start_tool_streaming
            # finish bookkeeping (streaming session registration, etc.).
            # We just suppressed the legacy "Executing Command" panel.
            return call_id or f"call_{str(uuid.uuid4())[:8]}"
        except Exception:  # pragma: no cover — fall through to legacy
            pass

    if tool_name == "execute_code" and isinstance(args, dict) and "code" in args:
        local_console = Console()

        agent_name = token_info.get("agent_name", "Agent") if token_info else "Agent"
        code = args.get("code", "")
        language = args.get("language", "python")
        filename = args.get("filename", "exploit")

        extensions = {
            "python": "py",
            "php": "php",
            "bash": "sh",
            "shell": "sh",
            "ruby": "rb",
            "perl": "pl",
            "golang": "go",
            "go": "go",
            "javascript": "js",
            "js": "js",
            "typescript": "ts",
            "ts": "ts",
            "rust": "rs",
            "csharp": "cs",
            "cs": "cs",
            "java": "java",
            "kotlin": "kt",
            "c": "c",
            "cpp": "cpp",
            "c++": "cpp",
        }
        ext = extensions.get(language, "txt")

        workspace = args.get("workspace", "")
        environment = args.get("environment", "")

        if environment == "Container" and workspace:
            full_path = f"{workspace}/{filename}.{ext}"
        elif workspace:
            cwd = os.getcwd()
            if workspace == os.path.basename(cwd):
                full_path = os.path.join(cwd, f"{filename}.{ext}")
            else:
                full_path = f"{workspace}/{filename}.{ext}"
        else:
            full_path = os.path.join(os.getcwd(), f"{filename}.{ext}")

        code_syntax = Syntax(
            code,
            language,
            theme="monokai",
            line_numbers=True,
            background_color="#272822",
            indent_guides=True,
            word_wrap=True,
        )
        code_panel = Panel(
            code_syntax,
            title=f"[bold cyan]{agent_name}[/bold cyan] - Code saved to: [yellow]{full_path}[/yellow]",
            border_style="cyan",
            title_align="left",
            box=ROUNDED,
            padding=(0, 1),
        )

        local_console.print(code_panel)

        if not hasattr(cli_print_tool_output, "_streaming_sessions"):
            cli_print_tool_output._streaming_sessions = {}
        if call_id not in cli_print_tool_output._streaming_sessions:
            cli_print_tool_output._streaming_sessions[call_id] = {}
        cli_print_tool_output._streaming_sessions[call_id]["code_panel_shown"] = True
    else:
        initial_message = "Starting tool execution..."
        if is_parallel and tool_name == "run_command" and isinstance(args, dict):
            command = args.get("command", "")
            cmd_args = args.get("args", "")
            if command:
                initial_message = f"Executing: {command} {cmd_args}".strip()

        cli_print_tool_output(
            tool_name=tool_name,
            args=args,
            output=initial_message,
            call_id=call_id,
            execution_info={"status": "running", "start_time": time.time()},
            token_info=token_info,
            streaming=True,
        )

    return call_id


def update_tool_streaming(tool_name, args, output, call_id, token_info=None, progress_state=None):
    """Update a streaming tool execution with new output."""
    if tool_name and tool_name.startswith("_internal_"):
        return

    # Store progress state in global tracker for toolbar access
    if progress_state is not None:
        _ACTIVE_TOOL_PROGRESS[call_id] = progress_state

    is_parallel = False
    if token_info and isinstance(token_info, dict):
        agent_id = token_info.get("agent_id", "")
        if agent_id and agent_id.startswith("P") and agent_id[1:].isdigit():
            is_parallel = True

    if tool_name == "execute_code" and is_parallel:
        if (
            hasattr(cli_print_tool_output, "_streaming_sessions")
            and call_id in cli_print_tool_output._streaming_sessions
        ):
            cli_print_tool_output._streaming_sessions[call_id]["buffer"] = output
            cli_print_tool_output._streaming_sessions[call_id]["current_output"] = output
        return

    cli_print_tool_output(
        tool_name=tool_name,
        args=args,
        output=output,
        call_id=call_id,
        execution_info={"status": "running", "replace_buffer": True},
        token_info=token_info,
        streaming=True,
        progress_state=progress_state,
    )


def _render_simple_tool_completion(tool_name, args, output, execution_info, token_info):
    """Palette-B rendering path for non-execute_code tools.

    Replaces the legacy CAI-style nested panels (Executing Command +
    Completed wrapper + tool output) with the flat layout from
    `tool_call_renderer`:

        ▸ tool_name  args
          ✓ Ns · summary · /show N

    Long outputs (> 8 lines) are stored in tool_output_buffer for /show
    recall; short outputs render inline with a small cyan panel.
    """
    try:
        from kryon.repl.ui.tool_call_renderer import (
            render_tool_completion,
        )
        from kryon.repl.ui.tool_output_buffer import record
    except Exception:  # pragma: no cover
        return  # If the new path imports fail, fall through to legacy.

    local_console = Console()

    # Duration: prefer execution_info["tool_time"], fall back to total
    duration_s = 0.0
    if execution_info:
        duration_s = float(execution_info.get("tool_time") or execution_info.get("total_time") or 0.0)

    status_str = (execution_info or {}).get("status", "completed")
    if status_str in ("completed", "ok", "success"):
        status = "ok"
    elif status_str in ("error", "failed", "fail"):
        status = "error"
    else:
        status = "warn"

    output_str = output if isinstance(output, str) else (str(output) if output else "")

    # Bank the full output so /show can recover it.
    step_id = record(tool_name=tool_name, output=output_str)

    # Quick one-line summary derived from output if not provided.
    summary = ""
    if output_str:
        first_line = output_str.splitlines()[0].strip()
        # Very short first line is often a meaningful summary
        if 0 < len(first_line) <= 80:
            summary = first_line
        elif len(output_str) > 0:
            summary = f"{len(output_str.splitlines())} lines"

    render_tool_completion(
        tool_name=tool_name,
        duration_s=duration_s,
        status=status,
        summary=summary,
        output=output_str,
        console=local_console,
        step_id=step_id,
    )


def finish_tool_streaming(tool_name, args, output, call_id, execution_info=None, token_info=None):
    """Complete a streaming tool execution."""
    # Clean up progress state in finally to prevent memory leak
    _ACTIVE_TOOL_PROGRESS.pop(call_id, None)

    if tool_name and tool_name.startswith("_internal_"):
        return

    if token_info and isinstance(token_info, dict):
        agent_id = token_info.get("agent_id", "")
        if agent_id and agent_id.startswith("P") and agent_id[1:].isdigit():
            pass

    # NEW PATH (Fase 3): non-code tools use the palette-B renderer.
    # `execute_code` keeps its specialized syntax-highlighted path below
    # because the syntax-highlighted code panel is genuinely useful.
    if tool_name and tool_name != "execute_code":
        try:
            _render_simple_tool_completion(
                tool_name=tool_name,
                args=args,
                output=output,
                execution_info=execution_info,
                token_info=token_info,
            )
            # Mark the streaming session complete so the legacy bookkeeping stays sane.
            if (
                hasattr(cli_print_tool_output, "_streaming_sessions")
                and call_id in cli_print_tool_output._streaming_sessions
            ):
                cli_print_tool_output._streaming_sessions[call_id]["is_complete"] = True
            return
        except Exception:  # pragma: no cover — fall through to legacy on any error
            pass

    if tool_name == "execute_code" and isinstance(args, dict) and "code" in args:
        local_console = Console()

        agent_name = token_info.get("agent_name", "Agent") if token_info else "Agent"
        language = args.get("language", "python")
        filename = args.get("filename", "code")

        extensions = {
            "python": "py",
            "php": "php",
            "bash": "sh",
            "shell": "sh",
            "ruby": "rb",
            "perl": "pl",
            "golang": "go",
            "go": "go",
            "javascript": "js",
            "js": "js",
            "typescript": "ts",
            "ts": "ts",
            "rust": "rs",
            "csharp": "cs",
            "cs": "cs",
            "java": "java",
            "kotlin": "kt",
            "c": "c",
            "cpp": "cpp",
            "c++": "cpp",
        }
        ext = extensions.get(language, "txt")

        workspace = ""
        if isinstance(args, dict) and "workspace" in args:
            workspace = args.get("workspace", "")
        elif execution_info and "workspace" in execution_info:
            workspace = execution_info.get("workspace", "")

        environment = ""
        if isinstance(args, dict) and "environment" in args:
            environment = args.get("environment", "")
        elif execution_info and "environment" in execution_info:
            environment = execution_info.get("environment", "")

        if environment == "Container" and workspace:
            pass
        elif workspace:
            cwd = os.getcwd()
            if workspace == os.path.basename(cwd):
                os.path.join(cwd, f"{filename}.{ext}")
            else:
                pass
        else:
            os.path.join(os.getcwd(), f"{filename}.{ext}")

        output_syntax = Syntax(
            output or "No output",
            "text",
            theme="monokai",
            background_color="#272822",
            word_wrap=True,
        )

        status = execution_info.get("status", "completed") if execution_info else "completed"
        if status == "completed":
            output_border_style = "green"
            output_title = f"[bold green]{agent_name}[/bold green] - Output"
        else:
            output_border_style = "red"
            output_title = f"[bold red]{agent_name}[/bold red] - Output (Error)"

        output_panel = Panel(
            output_syntax,
            title=output_title,
            border_style=output_border_style,
            title_align="left",
            box=ROUNDED,
            padding=(0, 1),
        )

        local_console.print(output_panel)

        if (
            hasattr(cli_print_tool_output, "_streaming_sessions")
            and call_id in cli_print_tool_output._streaming_sessions
        ):
            cli_print_tool_output._streaming_sessions[call_id]["is_complete"] = True
            cli_print_tool_output._streaming_sessions[call_id]["special_output_shown"] = True

        if hasattr(cli_print_tool_output, "_displayed_commands"):
            command_key = f"execute_code:{args.get('filename', 'code')}:{args.get('language', 'unknown')}"
            cli_print_tool_output._displayed_commands.add(command_key)

        return

    if execution_info is None:
        execution_info = {}

    execution_info["status"] = execution_info.get("status", "completed")
    execution_info["is_final"] = True
    execution_info["replace_buffer"] = True

    if hasattr(cli_print_tool_output, "_streaming_sessions") and call_id in cli_print_tool_output._streaming_sessions:
        session = cli_print_tool_output._streaming_sessions[call_id]
        if "start_time" in session and "tool_time" not in execution_info:
            execution_info["tool_time"] = time.time() - session["start_time"]

    if token_info:
        input_tokens = token_info.get("interaction_input_tokens", 0)
        output_tokens = token_info.get("interaction_output_tokens", 0)
        interaction_cost = token_info.get("interaction_cost", 0)

        if not interaction_cost and input_tokens > 0:
            model_name = token_info.get("model", os.environ.get("KRYON_MODEL", "kryon-local"))
            interaction_cost = calculate_model_cost(model_name, input_tokens, output_tokens)

        if input_tokens > 0:
            if _hide_cost():
                compact_tokens = f"\n[Tokens: I:{input_tokens} O:{output_tokens}]"
            else:
                compact_tokens = f"\n[Tokens: I:{input_tokens} O:{output_tokens} | Cost: ${interaction_cost:.4f}]"
            if output:
                if not output.endswith("\n"):
                    output += "\n"
                output += compact_tokens
            else:
                output = compact_tokens

    cli_print_tool_output(
        tool_name=tool_name,
        args=args,
        output=output,
        call_id=call_id,
        execution_info=execution_info,
        token_info=token_info,
        streaming=True,
    )

    if hasattr(cli_print_tool_output, "_streaming_sessions") and call_id in cli_print_tool_output._streaming_sessions:
        cli_print_tool_output._streaming_sessions[call_id]["is_complete"] = True
