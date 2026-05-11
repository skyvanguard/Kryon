"""`/show <N>` — recover a tool output that was collapsed by the renderer.

When `render_tool_completion` collapses an output > 8 lines into the
buffer, the user can read it with:

    /show 3            ← step 3's full output

The buffer resets on every new turn, so step ids are valid only for
the current turn.
"""

from __future__ import annotations

from rich.console import Console

from kryon.repl.commands.base import Command, register_command

console = Console()


class ShowCommand(Command):
    """Recover the full output of a previously-collapsed tool step."""

    def __init__(self) -> None:
        super().__init__(
            name="/show",
            description="Show the full output of a previously-collapsed tool step",
        )

    def handle(self, args: list[str] | None = None) -> bool:
        if not args:
            console.print(
                "[red]Usage: /show <step_number>[/red]\n"
                "[dim]Step numbers come from the '/show N' hints in tool "
                "completion lines this turn.[/dim]"
            )
            return False

        try:
            step_id = int(args[0])
        except ValueError:
            console.print(
                f"[red]/show expects a step number, got: {args[0]!r}[/red]"
            )
            return False

        try:
            from kryon.repl.ui.tool_call_renderer import render_collapsed_output
            from kryon.repl.ui.tool_output_buffer import get
        except Exception as e:
            console.print(f"[red]/show subsystem unavailable: {e}[/red]")
            return False

        entry = get(step_id)
        if entry is None:
            console.print(
                f"[yellow]No collapsed output for step {step_id}.[/yellow]\n"
                "[dim]The buffer resets each new turn — step ids are only "
                "valid for the current turn's tool calls.[/dim]"
            )
            return True

        render_collapsed_output(
            full_output=entry["output"],
            step_id=step_id,
            tool_name=entry["tool_name"],
            console=console,
        )
        return True


register_command(ShowCommand())
