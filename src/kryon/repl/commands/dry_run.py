"""Dry-run mode toggle for KRYON REPL.

When enabled, destructive commands (rm -rf, mkfs, systemctl stop sshd, DROP
TABLE, etc.) are simulated by `run_command` instead of executed. Used during
remediation playbooks (e.g. `server-hardening`) for safe previews.
"""

from __future__ import annotations

import os

from rich.console import Console

from kryon.repl.commands.base import Command, register_command

console = Console()

_TRUTHY = {"1", "true", "yes", "on"}


def _is_on() -> bool:
    return os.getenv("KRYON_DRY_RUN", "false").strip().lower() in _TRUTHY


class DryRunCommand(Command):
    """Toggle dry-run mode (`KRYON_DRY_RUN` env var)."""

    def __init__(self) -> None:
        super().__init__(
            name="/dry-run",
            description="Toggle dry-run mode for destructive commands",
        )
        self.add_subcommand("on", "Enable dry-run — destructive commands simulated", self.handle_on)
        self.add_subcommand("off", "Disable dry-run — commands execute normally", self.handle_off)
        self.add_subcommand("status", "Show current dry-run mode", self.handle_status)

    def handle_no_args(self) -> bool:
        return self.handle_status(None)

    def handle_unknown_subcommand(self, subcommand: str) -> bool:
        console.print(f"[red]Unknown subcommand: {subcommand}[/red]")
        console.print("Usage: /dry-run [on|off|status]")
        return False

    def handle_on(self, args: list[str] | None = None) -> bool:
        os.environ["KRYON_DRY_RUN"] = "true"
        console.print("[green]🔒 Dry-run mode ON — destructive commands will be simulated[/green]")
        return True

    def handle_off(self, args: list[str] | None = None) -> bool:
        os.environ["KRYON_DRY_RUN"] = "false"
        console.print("[yellow]⚠️  Dry-run mode OFF — destructive commands will execute normally[/yellow]")
        return True

    def handle_status(self, args: list[str] | None = None) -> bool:
        if _is_on():
            console.print("[green]Dry-run mode: ON[/green]")
        else:
            console.print("[yellow]Dry-run mode: OFF[/yellow]")
        return True


register_command(DryRunCommand())
