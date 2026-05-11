"""Tool call rendering primitives — palette B, hybrid layout.

Replaces the legacy CAI-fork pattern of 3 nested panels per tool call
(`Executing Command` → `Tool Output` → `Completed wrapper`) with a
flat layout:

  ▸ tool_name  args
    ╭ output ─────────╮          (only when output ≤ 8 lines)
    │ <body>          │
    ╰─────────────────╯
    ✓ Ns · summary · /show N     (when output > 8 lines, body collapsed)

Three primitives:
  * render_tool_invocation       — line 1, "▸ name  args"
  * render_tool_completion       — line 2 + optional inline panel / collapse hint
  * render_collapsed_output      — printed via `/show N` to reveal saved output

Plus a helper:
  * summarize_args               — extract the "important" arg(s) from kwargs

All helpers degrade gracefully on bad input — never raise from the
renderer when the agent emits an unexpected shape.
"""

from __future__ import annotations

import json
from typing import Any

from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Output above this line count is collapsed with /show hint.
COLLAPSE_THRESHOLD_LINES = 8

# Hard cap on the args summary in the invocation line — beyond this we ellipse.
MAX_ARGS_SUMMARY_CHARS = 100

# Per-tool: which arg key carries the "primary" value (the one worth
# showing alone in the invocation line). Any tool not listed falls
# back to a generic key=value summary.
_PRIMARY_ARG: dict[str, str] = {
    "run_command": "command",
    "execute_code": "code",
    "nmap": "target",
    "whatweb_scan": "target",
    "nuclei_scan": "target",
    "feroxbuster_scan": "target",
    "sqlmap_scan": "target",
    "http_fetch": "url",
    "curl": "url",
    "search_vulnerabilities": "query",
    "duckduckgo_search": "query",
    "recall_similar_experiences": "host_or_profile",
    "add_to_memory_semantic": "texts",
    "query_knowledge_base": "query",
}


# ---------------------------------------------------------------------------
# Argument summarization
# ---------------------------------------------------------------------------


def summarize_args(tool_name: str, args: Any) -> str:
    """Extract a one-line readable summary from a tool's args.

    Strategy:
      1. If a primary arg is registered for the tool, return its value verbatim.
      2. Otherwise, render the dict as `k=v · k=v` (boolean defaults skipped).
      3. JSON strings get parsed and processed as dicts.
      4. None / empty → "".

    The output gets truncated to MAX_ARGS_SUMMARY_CHARS by the caller's
    invocation line, but we keep this helper itself unrestricted so
    `/show` semantics work on the full args.
    """
    if not args:
        return ""

    # Parse JSON-string args (some SDK paths preserve the raw json)
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (json.JSONDecodeError, TypeError):
            return args  # opaque string — return as-is

    if not isinstance(args, dict):
        return str(args)

    # Primary-arg shortcut
    primary_key = _PRIMARY_ARG.get(tool_name)
    if primary_key and primary_key in args:
        value = args[primary_key]
        # Drop boring kwargs from suffix; only show extras meaningful to user.
        extras = {k: v for k, v in args.items() if k != primary_key and v not in (None, False, "", 0)}
        if extras:
            extras_str = " · ".join(f"{k}={v}" for k, v in extras.items())
            return f"{value}  ({extras_str})"
        return str(value)

    # Generic fallback — k=v · k=v
    parts: list[str] = []
    for k, v in args.items():
        if v in (None, False, "", 0):
            continue
        parts.append(f"{k}={v}")
    return " · ".join(parts)


def _truncate(s: str, max_chars: int = MAX_ARGS_SUMMARY_CHARS) -> str:
    """Bound the args summary to avoid wrap-over-multiple-lines."""
    if len(s) <= max_chars:
        return s
    return s[: max_chars - 1] + "…"


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def render_tool_invocation(
    *,
    tool_name: str,
    args_summary: str,
    console: Console,
) -> None:
    """Print the line that fires when a tool starts:  ▸ name  args"""
    truncated = _truncate(args_summary or "")
    line = Text()
    line.append("▸ ", style="cyan")
    line.append(tool_name, style="bold cyan")
    if truncated:
        line.append("  ")
        line.append(truncated, style="white")
    console.print(line)


def render_tool_completion(
    *,
    tool_name: str,
    duration_s: float,
    status: str,
    summary: str,
    output: str | None,
    console: Console,
    step_id: int | None = None,
) -> None:
    """Print the completion line and (when applicable) a small inline
    panel with the output, OR a collapsed marker pointing to /show N.

    Args:
        tool_name: same name as the invocation line.
        duration_s: wall-clock seconds.
        status: "ok" | "error" | "warn".
        summary: one-liner that goes on the completion line itself
            (e.g. "5 ports open" / "exit 1" / "3 prior experiences").
        output: the full output. None or empty → no panel.
        step_id: positional step number in the turn; required for the
            /show <N> collapse hint to work. None → output rendered
            inline regardless of size, no /show hint.
    """
    # Status-driven marker + style
    if status == "error":
        marker = "✗"
        marker_style = "red"
    elif status == "warn":
        marker = "!"
        marker_style = "yellow"
    else:  # ok / unknown → cyan (palette B default)
        marker = "✓"
        marker_style = "cyan"

    line = Text()
    line.append(f"  {marker} ", style=marker_style)
    line.append(f"{duration_s:.1f}s", style="dim")
    if summary:
        line.append("  ·  ", style="dim")
        line.append(summary, style="white")

    output = output or ""
    output_lines = output.splitlines() if output else []
    line_count = len(output_lines)

    if line_count == 0:
        # No output — single completion line.
        console.print(line)
        return

    # Decide inline panel vs collapse.
    if line_count > COLLAPSE_THRESHOLD_LINES and step_id is not None:
        # Collapse: print summary line + collapse hint, no body.
        line.append("  ·  ", style="dim")
        line.append(f"{line_count} lines", style="dim cyan")
        line.append("  ·  ", style="dim")
        line.append(f"/show {step_id}", style="dim cyan")
        console.print(line)
        return

    # Inline panel — output ≤ threshold OR no step_id available.
    console.print(line)
    panel_body = Text(output, style="white")
    panel = Panel(
        panel_body,
        title="output",
        title_align="left",
        border_style="cyan",
        box=ROUNDED,
        padding=(0, 1),
        expand=False,
    )
    console.print(panel)


def render_collapsed_output(
    *,
    full_output: str,
    step_id: int,
    tool_name: str,
    console: Console,
) -> None:
    """Triggered by `/show N` — print the previously-collapsed output.

    Layout:
      ── /show 5 · run_command ──────────────────────
      <full body>
      ────────────────────────────────────────────
    """
    from rich.rule import Rule

    title = f"/show {step_id} · {tool_name}"
    console.print(Rule(title=title, style="dim cyan", align="left"))

    if not full_output or not full_output.strip():
        console.print("[dim](no output)[/dim]")
    else:
        console.print(Text(full_output, style="white"))

    console.print(Rule(style="dim cyan"))
