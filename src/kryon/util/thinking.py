"""
Claude/AI thinking display utilities for KRYON.

This module provides functions for displaying AI reasoning/thinking
processes in the terminal with Rich panels.
"""

import os
import shutil
import time
import uuid
from datetime import datetime

from rich.box import ROUNDED
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

# Create console for thinking displays
console = Console()

# Global tracker for Claude thinking streaming panels
_CLAUDE_THINKING_PANELS: dict[str, dict] = {}


def create_claude_thinking_context(agent_name, counter, model):
    """
    Create a streaming context for AI thinking/reasoning display.
    This creates a dedicated panel that shows the model's internal reasoning process.

    Args:
        agent_name: The name of the agent
        counter: The interaction counter
        model: The model name

    Returns:
        A dictionary with the streaming context for thinking display
    """
    # Generate unique thinking context ID
    thinking_id = f"thinking_{agent_name}_{counter}_{str(uuid.uuid4())[:8]}"

    # Check if we already have an active thinking panel
    if thinking_id in _CLAUDE_THINKING_PANELS:
        return _CLAUDE_THINKING_PANELS[thinking_id]

    try:
        timestamp = datetime.now().strftime("%H:%M:%S")

        # Terminal size for better display
        terminal_width, _ = shutil.get_terminal_size((100, 24))
        panel_width = min(terminal_width - 4, 120)

        # Determine model type for display
        model_str = str(model).lower()
        if "claude" in model_str:
            model_display = "Claude"
        elif "deepseek" in model_str:
            model_display = "DeepSeek"
        else:
            model_display = "AI"

        # Create the thinking panel header
        header = Text()
        header.append("🧠 ", style="bold yellow")
        header.append(f"{model_display} Reasoning [{counter}]", style="bold yellow")
        header.append(f" | {agent_name}", style="bold cyan")
        header.append(f" | {timestamp}", style="dim")

        # Initial thinking content
        thinking_content = Text("Thinking...", style="italic dim")

        # Create the panel for thinking
        panel = Panel(
            Group(header, Text("\n"), thinking_content),
            title=f"[bold yellow]🧠 {model_display} Thinking Process[/bold yellow]",
            border_style="yellow",
            box=ROUNDED,
            padding=(1, 2),
            width=panel_width,
            expand=True,
        )

        # Create Live display object
        live = Live(panel, refresh_per_second=8, console=console, auto_refresh=True)

        context = {
            "thinking_id": thinking_id,
            "live": live,
            "panel": panel,
            "header": header,
            "thinking_content": thinking_content,
            "timestamp": timestamp,
            "model": model,
            "model_display": model_display,
            "agent_name": agent_name,
            "panel_width": panel_width,
            "is_started": False,
            "accumulated_thinking": "",
        }

        # Store in global tracker
        _CLAUDE_THINKING_PANELS[thinking_id] = context

        return context

    except Exception as e:
        print(f"Error creating {model_display} thinking context: {e}")
        return None


def update_claude_thinking_content(context, thinking_delta):
    """
    Update the AI thinking content with new reasoning text.

    Args:
        context: The thinking context created by create_claude_thinking_context
        thinking_delta: The new thinking text to add
    """
    if not context:
        return False

    try:
        # Accumulate the thinking text
        context["accumulated_thinking"] += thinking_delta

        # Try to format as markdown-like reasoning
        thinking_text = context["accumulated_thinking"]

        # Create formatted thinking display
        if len(thinking_text) > 500:
            # For long thinking, use syntax highlighting
            thinking_display = Syntax(
                thinking_text,
                "markdown",
                theme="monokai",
                background_color="#2E2E2E",
                word_wrap=True,
                line_numbers=False,
            )
        else:
            # For short thinking, use regular text with styling
            thinking_display = Text(thinking_text, style="white")

        # Get model display name from context
        model_display = context.get("model_display", "AI")

        # Update the panel content
        updated_panel = Panel(
            Group(context["header"], Text("\n"), thinking_display),
            title=f"[bold yellow]🧠 {model_display} Thinking Process[/bold yellow]",
            border_style="yellow",
            box=ROUNDED,
            padding=(1, 2),
            width=context.get("panel_width", 100),
            expand=True,
        )

        # Start the display if not already started
        if not context.get("is_started", False):
            try:
                context["live"].start()
                context["is_started"] = True
            except Exception as e:
                model_display = context.get("model_display", "AI")
                print(f"Error starting {model_display} thinking display: {e}")
                return False

        # Update the live display
        context["live"].update(updated_panel)
        context["panel"] = updated_panel
        context["live"].refresh()

        return True

    except Exception as e:
        model_display = context.get("model_display", "AI")
        print(f"Error updating {model_display} thinking content: {e}")
        return False


def finish_claude_thinking_display(context):
    """
    Finish the AI thinking display session.

    Args:
        context: The thinking context to finish
    """
    if not context:
        return False

    # Clean up from global tracker
    thinking_id = context.get("thinking_id")
    if thinking_id and thinking_id in _CLAUDE_THINKING_PANELS:
        del _CLAUDE_THINKING_PANELS[thinking_id]

    try:
        # Get model display name
        model_display = context.get("model_display", "AI")

        # Add final formatting to show completion
        final_header = Text()
        final_header.append("🧠 ", style="bold green")
        final_header.append(f"{model_display} Reasoning Complete", style="bold green")
        final_header.append(f" | {context['agent_name']}", style="bold cyan")
        final_header.append(f" | {context['timestamp']}", style="dim")

        thinking_text = context["accumulated_thinking"]

        if thinking_text.strip():
            # Create final formatted display
            final_thinking_display = Syntax(
                thinking_text,
                "markdown",
                theme="monokai",
                background_color="#2E2E2E",
                word_wrap=True,
                line_numbers=False,
            )
        else:
            final_thinking_display = Text("No reasoning captured", style="dim italic")

        # Create final panel
        final_panel = Panel(
            Group(final_header, Text("\n"), final_thinking_display),
            title=f"[bold green]🧠 {model_display} Thinking Complete[/bold green]",
            border_style="green",
            box=ROUNDED,
            padding=(1, 2),
            width=context.get("panel_width", 100),
            expand=True,
        )

        # Update one last time
        if context.get("is_started", False):
            context["live"].update(final_panel)

            # Give a moment for the final panel to be seen
            time.sleep(0.3)

            # Stop the live display
            context["live"].stop()

        return True

    except Exception as e:
        model_display = context.get("model_display", "AI")
        print(f"Error finishing {model_display} thinking display: {e}")
        return False


def detect_claude_thinking_in_stream(model_name):
    """
    Detect if a model should show thinking/reasoning display.
    Applies to Claude and DeepSeek models with reasoning capability.

    Args:
        model_name: The model name to check

    Returns:
        bool: True if thinking display should be shown
    """
    if not model_name:
        return False

    model_str = str(model_name).lower()

    # Check for Claude models with reasoning capability
    # Claude 4 models (like claude-sonnet-4-20250514) support reasoning
    # Also check for explicit "thinking" in model name
    has_claude_reasoning = "claude" in model_str and (
        # Claude 4 models (sonnet-4, haiku-4, opus-4)
        "-4-" in model_str
        or "sonnet-4" in model_str
        or "haiku-4" in model_str
        or "opus-4" in model_str
        or
        # Legacy support for 3.7 and explicit thinking models
        "3.7" in model_str
        or "thinking" in model_str
    )

    # Check for DeepSeek models with reasoning capability.
    # Note: `deepseek-chat` is the non-thinking alias and must NOT match
    # — it routes to V4 Flash without thinking and emits no
    # reasoning_content. Matching it would render an empty thinking panel.
    has_deepseek_reasoning = (
        "deepseek" in model_str
        and "deepseek-chat" not in model_str
        and (
            # Legacy reasoner alias (deprecated 2026-07-24)
            "reasoner" in model_str
            or
            # Provider-routed names (e.g., openrouter/deepseek/deepseek-r1)
            "/" in model_str
            or
            # New bare V4 names — V4 Pro always has thinking; V4 Flash
            # supports thinking via the `thinking` request flag.
            "v4-pro" in model_str
            or
            # V4 Flash with explicit thinking marker
            ("v4-flash" in model_str and "thinking" in model_str)
            or
            # Explicit reasoning markers (R1 distills, thinking variants)
            "r1" in model_str
            or "thinking" in model_str
        )
    )

    # Groq reasoning families: Qwen3 (with <think> tags) and OpenAI's
    # GPT-OSS (with separate `reasoning` field). Exclude the smaller
    # gpt-oss-safeguard which is policy-only and not a general agent.
    has_groq_reasoning = (
        "qwen3" in model_str
        or "qwq" in model_str
        or ("gpt-oss" in model_str and "safeguard" not in model_str)
    )

    return has_claude_reasoning or has_deepseek_reasoning or has_groq_reasoning


def print_claude_reasoning_simple(reasoning_content, agent_name, model_name):
    """
    Print AI reasoning content in simple mode (no Rich panels).
    Used when KRYON_STREAM=False.

    Args:
        reasoning_content: The reasoning/thinking text
        agent_name: The agent name
        model_name: The model name
    """
    if not reasoning_content or not reasoning_content.strip():
        return

    # Determine model type for display
    model_str = str(model_name).lower()
    if "claude" in model_str:
        model_display = "Claude"
    elif "deepseek" in model_str:
        model_display = "DeepSeek"
    else:
        model_display = "AI"

    # Simple text output without Rich formatting
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"\n🧠 {model_display} Reasoning | {agent_name} | {model_name} | {timestamp}")
    print("=" * 60)
    print(reasoning_content)
    print("=" * 60 + "\n")


def start_claude_thinking_if_applicable(model_name, agent_name, counter):
    """
    Start AI thinking display if the model supports it AND streaming is enabled.
    Supports Claude and DeepSeek models with reasoning capabilities.

    Args:
        model_name: The model name
        agent_name: The agent name
        counter: The interaction counter

    Returns:
        The thinking context if created, None otherwise
    """
    # Only show thinking in streaming mode
    streaming_enabled = os.getenv("KRYON_STREAM", "false").lower() == "true"

    if streaming_enabled and detect_claude_thinking_in_stream(model_name):
        return create_claude_thinking_context(agent_name, counter, model_name)
    return None


def get_thinking_panels():
    """Get access to the global thinking panels dictionary."""
    return _CLAUDE_THINKING_PANELS


def cleanup_thinking_panels():
    """Clean up all active thinking panels."""
    for _thinking_id, context in list(_CLAUDE_THINKING_PANELS.items()):
        try:
            if context and context.get("live") and context.get("is_started"):
                context["live"].stop()
        except Exception:
            pass
    _CLAUDE_THINKING_PANELS.clear()
