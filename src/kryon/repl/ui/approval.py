"""Structured approval prompt for high-stakes actions.

Used when Kryon is about to run commands that modify remote systems (the
`safe-modification` / `server-hardening` flow, Fase 3 of the hardening
playbook). Shows a grouped, severity-coded summary so the operator can
decide quickly without parsing raw commands.

Design goals (from real demo scenarios — BCP, britimp staging):

- Non-technical stakeholder can read the summary and say yes/no.
- The exact command is always visible (no hidden execution).
- Reversibility is explicit (did we back up?).
- Destructive actions are colour-coded red, modifications yellow,
  reads/neutral green.
- Keyboard UX matches conventions operators already know: `y` approves,
  `N` (default) rejects, `d` opens full details, `a` aborts the whole
  session to avoid silent acceptance on confirmation fatigue.

This is a clean implementation of a common CLI approval pattern. No
code copied from any third-party source — just `rich` primitives and
standard terminal conventions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text


class ApprovalResult(str, Enum):
    """What the operator chose."""
    YES = "yes"
    NO = "no"
    ABORT = "abort"      # stop the whole engagement, not just this step
    DETAILS = "details"  # show full details, re-prompt


class Severity(str, Enum):
    DESTRUCTIVE = "destructive"  # rm -rf, mkfs, DROP TABLE, ...
    MODIFY = "modify"             # sed -i, systemctl reload, chmod, ...
    READ = "read"                 # cat, ls, ss, ...
    NEUTRAL = "neutral"


_SEV_STYLE = {
    Severity.DESTRUCTIVE: ("red bold", "⚠"),
    Severity.MODIFY: ("yellow", "●"),
    Severity.READ: ("green", "○"),
    Severity.NEUTRAL: ("dim", "·"),
}


@dataclass
class ProposedAction:
    """One step the agent wants to run."""

    command: str
    severity: Severity = Severity.MODIFY
    purpose: str = ""                 # human-readable, one line
    reversible: bool = False
    backup_path: str | None = None    # if a backup is part of the plan
    target_host: str = ""             # e.g. "admin@192.168.1.10"


@dataclass
class ApprovalRequest:
    """The bundle the operator approves or rejects as a unit."""

    title: str                              # e.g. "Aplicar 3 correcciones CRITICAL"
    subtitle: str = ""                      # e.g. target host / engagement id
    actions: list[ProposedAction] = field(default_factory=list)
    impact_notes: list[str] = field(default_factory=list)  # free-form bullets
    dry_run: bool = False                   # if True, prompt shows "[DRY-RUN]"


def _render_actions_table(actions: Iterable[ProposedAction]) -> Table:
    t = Table(show_header=True, header_style="bold",
              box=box.SIMPLE, padding=(0, 1), pad_edge=False)
    t.add_column("#", style="dim", width=3)
    t.add_column("Tipo", width=14)
    t.add_column("Acción")
    for i, a in enumerate(actions, 1):
        style, marker = _SEV_STYLE[a.severity]
        tag = Text(f"{marker} {a.severity.value}", style=style)
        purpose = (a.purpose or a.command)[:90]
        host = f" @{a.target_host}" if a.target_host else ""
        t.add_row(str(i), tag, f"{purpose}{host}")
    return t


def _render_detail_panel(req: ApprovalRequest) -> Panel:
    parts: list = []
    for i, a in enumerate(req.actions, 1):
        style, _ = _SEV_STYLE[a.severity]
        header = Text(f"[{i}] {a.purpose or a.command[:80]}", style=style)
        parts.append(header)
        parts.append(Syntax(a.command, "bash", theme="ansi_dark",
                            line_numbers=False, word_wrap=True))
        meta_bits: list[str] = []
        if a.target_host:
            meta_bits.append(f"host: {a.target_host}")
        meta_bits.append("reversible: " + ("sí" if a.reversible else "no"))
        if a.backup_path:
            meta_bits.append(f"backup: {a.backup_path}")
        parts.append(Text("    " + "  ·  ".join(meta_bits), style="dim"))
        parts.append(Text(""))  # spacer
    return Panel(Group(*parts), title="Detalle por acción",
                 border_style="cyan", box=box.ROUNDED)


def _severity_counts(actions: Iterable[ProposedAction]) -> dict[Severity, int]:
    counts: dict[Severity, int] = {}
    for a in actions:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    return counts


def _render_summary_panel(req: ApprovalRequest) -> Panel:
    counts = _severity_counts(req.actions)
    badge_line = Text()
    for sev in (Severity.DESTRUCTIVE, Severity.MODIFY, Severity.READ, Severity.NEUTRAL):
        n = counts.get(sev, 0)
        if not n:
            continue
        style, marker = _SEV_STYLE[sev]
        if badge_line.plain:
            badge_line.append("  ")
        badge_line.append(f"{marker} {n} {sev.value}", style=style)

    header = Text()
    if req.dry_run:
        header.append("[DRY-RUN] ", style="bold magenta")
    header.append(req.title, style="bold")
    if req.subtitle:
        header.append("\n")
        header.append(req.subtitle, style="dim")

    body = Group(
        header,
        Text(""),
        badge_line,
        Text(""),
        _render_actions_table(req.actions),
    )
    if req.impact_notes:
        impact = Text()
        for note in req.impact_notes:
            if impact.plain:
                impact.append("\n")
            impact.append(f"  • {note}", style="yellow")
        body = Group(body, Text(""), impact)

    border = "magenta" if req.dry_run else (
        "red" if counts.get(Severity.DESTRUCTIVE) else "yellow"
    )
    return Panel(body, title="Acción propuesta", border_style=border,
                 box=box.ROUNDED)


def ask_approval(
    request: ApprovalRequest,
    *,
    console: Console | None = None,
    default: ApprovalResult = ApprovalResult.NO,
) -> ApprovalResult:
    """Show the approval UI and block until the operator decides.

    Returns the operator's choice. `default` is what Enter accepts when the
    operator just hits return — defaults to NO because silent confirmation
    on destructive actions is the failure mode we're preventing.
    """
    con = console or Console()
    con.print()
    con.print(_render_summary_panel(request))

    prompt_suffix = (
        " [bold green]y[/]es / [bold red]N[/]o / [bold cyan]d[/]etalles / "
        "[bold]a[/]bort"
    )
    default_char = {
        ApprovalResult.YES: "y",
        ApprovalResult.NO: "N",
        ApprovalResult.ABORT: "a",
    }.get(default, "N")

    while True:
        try:
            raw = Prompt.ask(
                f"¿Aplicar?{prompt_suffix}",
                default=default_char, show_default=False, console=con,
            )
        except (KeyboardInterrupt, EOFError):
            con.print("\n[red]cancelado[/red]")
            return ApprovalResult.ABORT

        choice = (raw or default_char).strip().lower()[:1]
        if choice == "y":
            return ApprovalResult.YES
        if choice in ("n", ""):
            return ApprovalResult.NO
        if choice == "a":
            return ApprovalResult.ABORT
        if choice == "d":
            con.print(_render_detail_panel(request))
            continue
        con.print(f"[dim]entrada inválida: {raw!r}. Responder y/N/d/a.[/dim]")


def ask_yes_no(
    question: str,
    *,
    default: bool = False,
    console: Console | None = None,
) -> bool:
    """Lightweight variant for simple confirmations (no action bundle).

    Use `ask_approval` whenever commands are involved. This is for pure
    control-flow confirmations like "continuar al siguiente host?"."""
    con = console or Console()
    default_char = "Y" if default else "N"
    while True:
        try:
            raw = Prompt.ask(
                f"{question} [bold green]y[/]/[bold red]N[/]",
                default=default_char, show_default=False, console=con,
            )
        except (KeyboardInterrupt, EOFError):
            return False
        ch = (raw or default_char).strip().lower()[:1]
        if ch == "y":
            return True
        if ch in ("n", ""):
            return False
