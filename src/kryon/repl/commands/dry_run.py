"""
/dry-run — Toggle dry-run mode for destructive command simulation.

When dry-run is ON:
- Destructive commands (rm -rf, DROP TABLE, dd, mkfs, shutdown, etc.)
  are NOT executed
- The model receives "[DRY-RUN] Would execute: ..." + classification
- Caution commands (sed -i, apt install, systemctl restart) also simulated

Use this before running server-hardening or any remediation flow to
preview what would change without actually applying anything.
"""

from __future__ import annotations

import os
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from kryon.repl.commands.base import Command, register_command

console = Console()


class DryRunCommand(Command):
    """Toggle dry-run mode — prevents execution of destructive commands."""

    def __init__(self):
        super().__init__(
            name="/dry-run",
            description="Preview destructive commands without executing them",
            aliases=["/dryrun"],
        )
        self.add_subcommand("on", "Enable dry-run mode", self.handle_on)
        self.add_subcommand("off", "Disable dry-run mode", self.handle_off)
        self.add_subcommand("status", "Show current dry-run state", self.handle_status)

    def handle_no_args(self) -> bool:
        """Default: show status."""
        return self.handle_status()

    def handle_on(self, args: Optional[list[str]] = None) -> bool:
        os.environ["KRYON_DRY_RUN"] = "true"
        console.print(
            Panel(
                "[bold green]🔒 Dry-run mode ON[/bold green]\n\n"
                "Destructive commands (rm -rf, DROP TABLE, dd, mkfs, systemctl stop sshd, etc.)\n"
                "will be [bold]simulated, not executed[/bold].\n\n"
                "The model will see [cyan][DRY-RUN] Would execute: ...[/cyan] for these commands.\n\n"
                "[dim]Use this before running server-hardening or remediation flows.[/dim]",
                title="/dry-run on",
                border_style="green",
            )
        )
        return True

    def handle_off(self, args: Optional[list[str]] = None) -> bool:
        os.environ["KRYON_DRY_RUN"] = "false"
        console.print(
            Panel(
                "[bold yellow]⚠️  Dry-run mode OFF[/bold yellow]\n\n"
                "Commands will execute normally. Destructive operations may\n"
                "permanently modify your system.\n\n"
                "[dim]Use [bold]/dry-run on[/bold] to re-enable safety mode.[/dim]",
                title="/dry-run off",
                border_style="yellow",
            )
        )
        return True

    def handle_status(self, args: Optional[list[str]] = None) -> bool:
        is_on = os.environ.get("KRYON_DRY_RUN", "").lower() in ("true", "1", "yes")
        if is_on:
            console.print(
                Panel(
                    "[bold green]🔒 Dry-run mode is ON[/bold green]\n"
                    "Destructive commands are being simulated.",
                    title="/dry-run status",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    "[bold yellow]⚠️  Dry-run mode is OFF[/bold yellow]\n"
                    "Commands execute normally.\n\n"
                    "[dim]Enable with [bold]/dry-run on[/bold] before remediation flows.[/dim]",
                    title="/dry-run status",
                    border_style="yellow",
                )
            )
        return True


register_command(DryRunCommand())
