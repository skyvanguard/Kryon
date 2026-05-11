"""Live progress display for long-running recon commands.

Wraps subprocess execution in a `rich.live` panel showing:

- Spinner + elapsed time
- Tool name (auto-detected from command)
- Parsed progress (percentage when tool emits it, line count otherwise)
- Last status phrase (nmap phase, masscan rate+found, rustscan open port)
- Tail window of the last 4 output lines

Designed for the britimp demo where `nmap -sV /24` takes 3-10 min: the
operator must see Kryon is working, not staring at a frozen terminal.

Not a full TUI — `rich.live` handles the redraws, and the subprocess
streams stdout line-by-line.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

logger = logging.getLogger(__name__)

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from kryon.repl.ui.progress import (
    ProgressState,
    format_progress_bar,
    get_parser_for_command,
)


@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    lines_emitted: int


def _elapsed_str(seconds: float) -> str:
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:d}:{s:02d}"


def _render_panel(
    command: str,
    tool_name: str,
    state: ProgressState,
    started_at: float,
    tail: deque[str],
    spinner: Spinner,
) -> Panel:
    elapsed = time.time() - started_at
    bar = format_progress_bar(state, width=32)

    header_tbl = Table(show_header=False, box=None, padding=(0, 1), pad_edge=False)
    header_tbl.add_column(justify="left")
    header_tbl.add_column(justify="right")
    header_tbl.add_row(
        Group(spinner, Text(f" {tool_name}", style="bold cyan")),
        Text(_elapsed_str(elapsed), style="dim"),
    )

    bar_text = Text.from_markup(f"  {bar}")
    cmd_line = Text(f"  $ {command[:100]}", style="dim")

    tail_block: Text | None = None
    if tail:
        tail_lines = "\n".join(f"    {ln[:110]}" for ln in tail)
        tail_block = Text(tail_lines, style="dim white")

    children: list = [header_tbl, bar_text, cmd_line]
    if tail_block is not None:
        children.append(Text(""))
        children.append(tail_block)

    return Panel(
        Group(*children),
        title="[bold]recon[/bold]",
        border_style="cyan",
        box=box.ROUNDED,
    )


def run_with_progress(
    command: str,
    *,
    shell: bool = True,
    timeout_s: int | None = None,
    console: Console | None = None,
    tail_size: int = 4,
    on_line: Callable[[str], None] | None = None,
) -> CommandResult:
    """Run a command, stream stdout, render a live progress panel.

    Args:
        command: shell command to execute.
        shell: if True, runs via /bin/sh -c.
        timeout_s: optional wall-clock timeout; process is killed if exceeded.
        console: rich Console (default stdout).
        tail_size: number of recent stdout lines to show under the bar.
        on_line: optional callback invoked with each raw stdout line
                 (for plugging into logging / file writes).

    Returns: CommandResult with returncode, captured stdout+stderr, and
             elapsed duration.

    On KeyboardInterrupt: best-effort terminates the child process and
    re-raises the exception so the caller can decide what to do.
    """
    con = console or Console()
    parser = get_parser_for_command(command)
    state = ProgressState(tool_name=parser.name)
    tail: deque[str] = deque(maxlen=tail_size)
    stdout_buf: list[str] = []
    stderr_buf: list[str] = []
    spinner = Spinner("dots", style="cyan")
    started = time.time()

    proc = subprocess.Popen(
        command if shell else command.split(),
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    # Drain stderr in a background thread so the child never blocks
    # writing to a full stderr pipe while we're busy consuming stdout.
    # Prior implementation read stderr only AFTER the stdout loop, which
    # deadlocks on tools that emit lots of stderr warnings (nikto,
    # wpscan --verbose) when that output exceeds the kernel pipe buffer.
    def _drain_stderr() -> None:
        if proc.stderr is None:
            return
        try:
            for chunk in iter(proc.stderr.readline, ""):
                if not chunk:
                    break
                stderr_buf.append(chunk)
        except Exception as exc:  # noqa: BLE001
            logger.debug("stderr drainer: %s", exc)

    stderr_thread = threading.Thread(
        target=_drain_stderr,
        name="live-progress-stderr",
        daemon=True,
    )
    stderr_thread.start()

    try:
        with Live(
            _render_panel(command, parser.name, state, started, tail, spinner),
            refresh_per_second=8,
            console=con,
            transient=False,
        ) as live:
            if proc.stdout is None:
                raise RuntimeError("Popen returned without a stdout pipe")
            for raw_line in proc.stdout:
                line = raw_line.rstrip("\r\n")
                stdout_buf.append(raw_line)
                tail.append(line)
                state = parser.parse_line(line, state)
                if on_line is not None:
                    try:
                        on_line(raw_line)
                    except Exception as exc:  # noqa: BLE001 — user code
                        logger.debug("on_line callback raised: %s", exc)

                # Soft timeout: bail before reading more lines if exceeded.
                if timeout_s is not None and (time.time() - started) > timeout_s:
                    proc.terminate()
                    break

                live.update(
                    _render_panel(
                        command,
                        parser.name,
                        state,
                        started,
                        tail,
                        spinner,
                    )
                )

            proc.wait()
            # Give the stderr drainer a short grace period to finish
            # reading any tail output the child wrote just before exit.
            stderr_thread.join(timeout=2)
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise

    duration = time.time() - started
    return CommandResult(
        command=command,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout="".join(stdout_buf),
        stderr="".join(stderr_buf),
        duration_s=duration,
        lines_emitted=state.total_lines,
    )
