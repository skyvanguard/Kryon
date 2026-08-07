"""TDD contract for kryon.repl.ui.tool_call_renderer.

Three rendering primitives that replace the legacy 3-nested-panel
shape from CAI fork. Goals:
  * 1 tool call (no output)            → 2 lines
  * 1 tool call (output ≤ 8 lines)     → ≤ 4 + N lines
  * 1 tool call (output > 8 lines)     → 3 lines collapsed
  * Status colors only on actual failure / warning — no green chrome.
"""

from __future__ import annotations

from io import StringIO
from typing import Any

import pytest


def _render_to_text(fn, *args, **kwargs) -> str:
    """Helper: invoke a renderer and capture stdout to text."""
    from rich.console import Console

    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=120, color_system=None)
    fn(*args, console=console, **kwargs)
    return buf.getvalue()


# ---------- render_tool_invocation ----------


def test_invocation_one_line() -> None:
    """Tool start = single line. No box, no panel."""
    from kryon.repl.ui.tool_call_renderer import render_tool_invocation

    out = _render_to_text(
        render_tool_invocation,
        tool_name="run_command",
        args_summary="echo 'hello'",
    )
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 1
    assert "run_command" in lines[0]
    assert "echo 'hello'" in lines[0]


def test_invocation_uses_arrow_marker() -> None:
    from kryon.repl.ui.tool_call_renderer import render_tool_invocation

    out = _render_to_text(
        render_tool_invocation,
        tool_name="nmap",
        args_summary="-sV target",
    )
    # Marker indicates "this tool is starting / running".
    assert "▸" in out or "→" in out or ">" in out


def test_invocation_truncates_long_args() -> None:
    """Args longer than terminal width get truncated with an ellipsis."""
    from kryon.repl.ui.tool_call_renderer import render_tool_invocation

    long_args = "x=" + "y" * 500
    out = _render_to_text(
        render_tool_invocation,
        tool_name="t",
        args_summary=long_args,
    )
    # Ellipsis or truncation marker present
    assert "…" in out or "..." in out
    # Output stays bounded
    longest = max((len(line) for line in out.splitlines()), default=0)
    assert longest <= 200


# ---------- render_tool_completion (no output) ----------


def test_completion_no_output_one_line() -> None:
    """Tool completed without output = single line summary."""
    from kryon.repl.ui.tool_call_renderer import render_tool_completion

    out = _render_to_text(
        render_tool_completion,
        tool_name="recall_similar_experiences",
        duration_s=29.0,
        status="ok",
        summary="3 prior experiences",
        output=None,
    )
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 1
    assert "✓" in out or "OK" in out
    assert "29" in out  # duration shows in seconds
    assert "3 prior experiences" in out


def test_completion_with_summary_and_no_output() -> None:
    from kryon.repl.ui.tool_call_renderer import render_tool_completion

    out = _render_to_text(
        render_tool_completion,
        tool_name="t",
        duration_s=0.5,
        status="ok",
        summary="done",
        output="",  # empty string also counts as no output
    )
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 1


# ---------- render_tool_completion (inline output ≤ 8 lines) ----------


def test_completion_short_output_renders_inline_panel() -> None:
    """≤ 8 lines = small panel inline below the summary line."""
    from kryon.repl.ui.tool_call_renderer import render_tool_completion

    short = "line 1\nline 2\nline 3"
    out = _render_to_text(
        render_tool_completion,
        tool_name="run_command",
        duration_s=0.0,
        status="ok",
        summary="3 lines",
        output=short,
    )
    # Body content present
    assert "line 1" in out
    assert "line 3" in out
    # Some kind of panel border drawn
    has_border = any(c in out for c in ("─", "│", "╭", "╰"))
    assert has_border


def test_completion_eight_line_output_still_inline() -> None:
    """Exactly 8 lines = boundary case, still inline."""
    from kryon.repl.ui.tool_call_renderer import render_tool_completion

    eight = "\n".join(f"row {i}" for i in range(8))
    out = _render_to_text(
        render_tool_completion,
        tool_name="t",
        duration_s=0.1,
        status="ok",
        summary="8 lines",
        output=eight,
    )
    # All 8 rows visible
    for i in range(8):
        assert f"row {i}" in out
    # No collapse marker since we're at threshold, not over.
    assert "/show" not in out


# ---------- render_tool_completion (collapsed > 8 lines) ----------


def test_completion_long_output_collapses_with_show_hint() -> None:
    """> 8 lines = collapsed marker. Body NOT printed inline."""
    from kryon.repl.ui.tool_call_renderer import render_tool_completion

    long = "\n".join(f"line {i}" for i in range(50))
    out = _render_to_text(
        render_tool_completion,
        tool_name="nmap",
        duration_s=12.5,
        status="ok",
        summary="5 ports open",
        output=long,
        step_id=3,
    )
    # Body content NOT all printed inline
    assert "line 49" not in out
    # Collapse marker mentions line count + step id
    assert "50" in out  # number of lines
    assert "/show 3" in out  # how to expand


def test_completion_collapse_requires_step_id() -> None:
    """If output > 8 lines and step_id is None, the renderer falls back
    to inline (we can't reference it for /show without an id)."""
    from kryon.repl.ui.tool_call_renderer import render_tool_completion

    long = "\n".join(f"line {i}" for i in range(50))
    out = _render_to_text(
        render_tool_completion,
        tool_name="t",
        duration_s=1.0,
        status="ok",
        summary="long",
        output=long,
        step_id=None,
    )
    # Without an id, rendering still works — line count still shown
    # but no /show hint.
    assert "/show" not in out


# ---------- Status colors ----------


def test_completion_status_error_uses_red_marker() -> None:
    """Error completion shows ✗ with red styling."""
    from rich.console import Console

    from kryon.repl.ui.tool_call_renderer import render_tool_completion

    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=120)
    render_tool_completion(
        tool_name="run_command",
        duration_s=0.5,
        status="error",
        summary="exit code 1",
        output=None,
        console=console,
    )
    text = buf.getvalue()
    assert "✗" in text or "ERR" in text or "FAIL" in text
    # Some red ANSI escape sequence somewhere
    assert "\x1b[31" in text or "\x1b[91" in text  # red or bright red


def test_completion_status_ok_uses_cyan_not_green() -> None:
    """Palette B: success uses cyan/dim, NOT green chrome.
    Green is reserved for explicit PASS in compliance reports only."""
    from rich.console import Console

    from kryon.repl.ui.tool_call_renderer import render_tool_completion

    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=120)
    render_tool_completion(
        tool_name="t",
        duration_s=0.5,
        status="ok",
        summary="done",
        output=None,
        console=console,
    )
    text = buf.getvalue()
    # Cyan ANSI present (36 base, 96 bright)
    assert "\x1b[36" in text or "\x1b[96" in text


# ---------- render_collapsed_output ----------


def test_collapsed_output_prints_full_body() -> None:
    """Triggered by `/show N` — prints the full body that was collapsed."""
    from kryon.repl.ui.tool_call_renderer import render_collapsed_output

    long = "\n".join(f"line {i}" for i in range(20))
    out = _render_to_text(
        render_collapsed_output,
        full_output=long,
        step_id=5,
        tool_name="run_command",
    )
    # All 20 lines present now
    for i in range(20):
        assert f"line {i}" in out
    # Header tells the user which step this is
    assert "5" in out
    assert "run_command" in out


def test_collapsed_output_handles_empty() -> None:
    """Edge case — `/show N` on empty buffer doesn't crash."""
    from kryon.repl.ui.tool_call_renderer import render_collapsed_output

    out = _render_to_text(
        render_collapsed_output,
        full_output="",
        step_id=1,
        tool_name="t",
    )
    # No crash, message indicates absence
    assert "empty" in out.lower() or "(no output)" in out.lower() or "1" in out


# ---------- Argument summarization ----------


def test_summarize_args_strips_python_repr_form() -> None:
    """`run_command(command='nmap -sV', interactive=False)` → `nmap -sV`."""
    from kryon.repl.ui.tool_call_renderer import summarize_args

    args = {"command": "nmap -sV target", "interactive": False}
    out = summarize_args("run_command", args)
    # Primary param surfaces; boilerplate doesn't.
    assert "nmap -sV target" in out
    # Don't drown the user with all kwargs as repr.
    assert "interactive=False" not in out or len(out) < 80


def test_summarize_args_for_compliance_audit() -> None:
    """Tool with framework + host should show 'framework=X host=Y'."""
    from kryon.repl.ui.tool_call_renderer import summarize_args

    args = {"framework": "fortigate", "host": "192.168.1.1"}
    out = summarize_args("run_compliance_audit", args)
    assert "fortigate" in out
    assert "192.168.1.1" in out


def test_summarize_args_handles_string_input() -> None:
    """Some callsites pass args as a JSON string already."""
    from kryon.repl.ui.tool_call_renderer import summarize_args

    out = summarize_args("t", '{"x": 1}')
    # Doesn't raise — at minimum returns the input or a derivative.
    assert isinstance(out, str)
    assert len(out) > 0


def test_summarize_args_empty() -> None:
    from kryon.repl.ui.tool_call_renderer import summarize_args

    assert summarize_args("t", {}) == ""
    assert summarize_args("t", "") == ""
    assert summarize_args("t", None) == ""


# ---------- Composition (visual goal: ≤ 5 lines per tool call) ----------


def test_full_tool_call_simple_output_is_compact() -> None:
    """End-to-end: invocation + completion with short output ≤ 7 lines."""
    from rich.console import Console

    from kryon.repl.ui.tool_call_renderer import (
        render_tool_completion,
        render_tool_invocation,
    )

    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=120, color_system=None)
    render_tool_invocation(
        tool_name="run_command",
        args_summary="echo hello",
        console=console,
    )
    render_tool_completion(
        tool_name="run_command",
        duration_s=0.0,
        status="ok",
        summary="1 line",
        output="hello",
        console=console,
    )
    out = buf.getvalue()
    line_count = len([line for line in out.splitlines() if line.strip()])
    # Target: ≤ 5 lines (invocation + summary + 3-line panel of "hello")
    # We allow up to 7 to be safe with rich's panel borders.
    assert line_count <= 7, f"compact target broken; got {line_count} lines:\n{out}"
