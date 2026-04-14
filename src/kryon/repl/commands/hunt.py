"""
/hunt — launch and manage 0-day hunts against git repos.

Subcommands:
  /hunt <repo_url> [--runner heuristic|llm] [--parallel N] [--budget K] [--ref SHA]
  /hunt status                  — show active hunters + current TODO list
  /hunt stop <hunter_id>        — cancel a running hunter
  /hunt report                  — pretty-print the last HuntReport
  /hunt last                    — alias for report

Output of the hunt goes to the console AND is saved at
/workspace/hunts/<timestamp>.json so later runs can reference it.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from kryon.repl.commands.base import Command, register_command

console = Console()

_HUNTS_DIR = Path(os.environ.get("KRYON_HUNTS_DIR", "/workspace/hunts"))
_LAST_REPORT_PATH = _HUNTS_DIR / "_last_report.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_flags(args: list[str]) -> tuple[list[str], dict]:
    """Separate positional args from --key value flags."""
    positional: list[str] = []
    flags: dict = {}
    i = 0
    while i < len(args):
        tok = args[i]
        if tok.startswith("--"):
            key = tok[2:]
            val = ""
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                val = args[i + 1]
                i += 2
            else:
                val = "true"
                i += 1
            flags[key] = val
        else:
            positional.append(tok)
            i += 1
    return positional, flags


def _save_report(report_json: str) -> Path:
    _HUNTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = _HUNTS_DIR / f"hunt_{ts}.json"
    path.write_text(report_json, encoding="utf-8")
    _LAST_REPORT_PATH.write_text(report_json, encoding="utf-8")
    return path


def _load_last_report() -> Optional[dict]:
    if not _LAST_REPORT_PATH.exists():
        return None
    try:
        return json.loads(_LAST_REPORT_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


class HuntCommand(Command):
    def __init__(self):
        super().__init__(
            name="/hunt",
            description="Launch / manage 0-day hunts (planner-hunter swarm)",
        )
        self.add_subcommand("status", "Show active hunters + TODO list", self.handle_status)
        self.add_subcommand("stop", "Cancel a running hunter by id", self.handle_stop)
        self.add_subcommand("report", "Pretty-print the last hunt report", self.handle_report)
        self.add_subcommand("last", "Alias for /hunt report", self.handle_report)

    def handle(self, args: Optional[list[str]] = None) -> bool:
        # If first arg is a URL (http...) or path, treat as positional launch
        if args and not args[0].startswith("/") and (
            args[0].startswith(("http://", "https://", "git@", "/"))
            or args[0] in ("status", "stop", "report", "last")
        ):
            if args[0] in self.subcommands:
                return super().handle(args)
            return self.handle_launch(args)
        return super().handle(args)

    # ------------------------------------------------------------------

    def handle_no_args(self) -> bool:
        console.print(
            "[yellow]/hunt usage:[/yellow]\n"
            "  [cyan]/hunt <repo_url>[/cyan] "
            "[--runner heuristic|llm] [--parallel N] [--budget K] [--ref SHA]\n"
            "  [cyan]/hunt status[/cyan]\n"
            "  [cyan]/hunt stop <hunter_id>[/cyan]\n"
            "  [cyan]/hunt report[/cyan]"
        )
        return True

    def handle_launch(self, args: list[str]) -> bool:
        positional, flags = _parse_flags(args)
        if not positional:
            return self.handle_no_args()

        repo_url = positional[0]
        runner_type = flags.get("runner", "heuristic").lower()
        if runner_type not in {"heuristic", "llm"}:
            console.print(f"[red]unknown runner: {runner_type!r} (use heuristic|llm)[/red]")
            return False

        try:
            parallel = int(flags.get("parallel", os.environ.get("KRYON_HUNTER_PARALLELISM", "2")))
        except ValueError:
            parallel = 2
        try:
            budget = int(flags.get("budget", "10"))
        except ValueError:
            budget = 10
        ref = flags.get("ref", "")

        console.print(
            f"[bold cyan]Launching hunt[/bold cyan]\n"
            f"  repo:        {repo_url}\n"
            f"  runner:      {runner_type}\n"
            f"  parallel:    {parallel}\n"
            f"  budget:      {budget} files\n"
            f"  ref:         {ref or '(HEAD)'}"
        )

        # Defer import to keep REPL startup light
        from kryon.skills.planner_hunter import hunt_zero_days

        try:
            report = asyncio.run(
                hunt_zero_days(
                    repo_url,
                    budget=budget,
                    parallelism=parallel,
                    runner_type=runner_type,
                    ref=ref,
                )
            )
        except Exception as e:
            console.print(f"[red]Hunt failed: {e}[/red]")
            return False

        path = _save_report(report.to_json())
        console.print()
        console.print(report.pretty())
        console.print()
        console.print(f"[dim]Report saved at {path}[/dim]")
        return True

    def handle_status(self, args: Optional[list[str]] = None) -> bool:
        from kryon.skills.supervisor_tools import get_pool, get_state

        pool = get_pool()
        state = get_state()
        actives = pool.list_active()
        queued = pool.list_queued()
        done = [j for j in pool.list_all() if j.status in ("finished", "failed", "terminated")]

        table = Table(title=f"Hunters (pool cap={pool.max_active})")
        table.add_column("id", style="cyan")
        table.add_column("file")
        table.add_column("status")
        table.add_column("dur", justify="right")
        table.add_column("findings", justify="right")
        for j in pool.list_all():
            table.add_row(
                j.hunter_id,
                Path(j.file_path).name if j.file_path else "",
                j.status,
                f"{j.duration_s():.1f}s",
                str(len(j.findings)),
            )
        console.print(table)
        console.print(
            f"[dim]active={len(actives)}  queued={len(queued)}  done={len(done)}  "
            f"notes={len(state.notes)}  todos={len(state.todos)}[/dim]"
        )
        if state.todos:
            console.print("[bold]TODO list (supervisor)[/bold]")
            for t in state.todos[:10]:
                console.print(
                    f"  [{t.get('status', '?')}] #{t.get('n', '?')} "
                    f"{t.get('file', '')}  (priority {t.get('priority', '?')})"
                )
        return True

    def handle_stop(self, args: Optional[list[str]] = None) -> bool:
        if not args:
            console.print("[yellow]usage: /hunt stop <hunter_id>[/yellow]")
            return False
        from kryon.skills.supervisor_tools import get_pool

        pool = get_pool()
        hunter_id = args[0]

        async def _term():
            return await pool.terminate(hunter_id, reason="stopped via /hunt")

        ok = asyncio.run(_term())
        if ok:
            console.print(f"[green]terminated hunter {hunter_id}[/green]")
        else:
            console.print(f"[red]could not terminate {hunter_id} (not found or done)[/red]")
        return ok

    def handle_report(self, args: Optional[list[str]] = None) -> bool:
        data = _load_last_report()
        if data is None:
            console.print("[yellow]No prior hunt report. Launch one with `/hunt <repo_url>`.[/yellow]")
            return False

        lines = [
            f"[bold cyan]=== Hunt Report: {data.get('repo_url', '?')} ===[/bold cyan]",
            f"  HEAD:            {data.get('head_sha', '')[:10]}",
            f"  duration:        {data.get('duration_s', '?')}s",
            f"  parallelism:     {data.get('parallelism', '?')} (runner={data.get('runner_type', '?')})",
            f"  files scored:    {data.get('files_scored', '?')}",
            f"  hunters spawned: {data.get('hunters_spawned', '?')}",
            f"  raw findings:    {data.get('raw_findings', '?')}",
            f"  [green]confirmed:       {data.get('confirmed_findings', 0)}[/green]",
            f"  [dim]rejected:        {data.get('rejected_findings', 0)}[/dim]",
        ]
        for line in lines:
            console.print(line)

        confirmed = [v for v in data.get("verdicts", []) if v.get("verdict") == "CONFIRMED"]
        if confirmed:
            console.print()
            console.print("[bold green]Confirmed findings[/bold green]")
            for v in confirmed:
                console.print(
                    f"  [{v.get('severity_actual', '?')}] "
                    f"{v.get('cwe_actual', ''):<10} "
                    f"{v.get('reproduced_crash_type', '?'):<25} "
                    f"{v.get('_file', '?')}::{v.get('_function', '?')}"
                )
                if v.get("classification_notes"):
                    console.print(f"      [dim]{v['classification_notes']}[/dim]")

        rejected = [v for v in data.get("verdicts", []) if v.get("verdict") == "REJECTED"]
        if rejected:
            console.print()
            console.print(
                f"[dim]{len(rejected)} rejected by validator: "
                + ", ".join(sorted({v.get("phase_failed", "?") for v in rejected}))
                + "[/dim]"
            )
        return True


# Register
register_command(HuntCommand())
