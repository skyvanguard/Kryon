"""
/experiences — KRYON self-improving loop REPL command.

Lets the operator:
  - /experiences                 → show count + last 10 summaries
  - /experiences list            → list last N experiences
  - /experiences show <id>       → full dump of one experience
  - /experiences search <query>  → similarity search by free text
  - /experiences delete <id>     → remove one experience
  - /experiences close [summary] → mine current session, persist as experience

See docs/LEARNING_LOOP.md for the architecture.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from kryon.repl.commands.base import Command, register_command
from kryon.sdk.agents.models.openai_chatcompletions import (
    get_agent_message_history,
    get_all_agent_histories,
)

console = Console()


class ExperiencesCommand(Command):
    """Manage KRYON engagement experiences (self-improving loop)."""

    def __init__(self):
        super().__init__(
            name="/experiences",
            description="Manage KRYON self-improving experience store",
            aliases=["/exp"],
        )
        self.add_subcommand("list", "List the most recent experiences", self.handle_list)
        self.add_subcommand("show", "Show one experience in full", self.handle_show)
        self.add_subcommand(
            "search", "Similarity search over experiences (free text)", self.handle_search
        )
        self.add_subcommand("delete", "Delete one experience by id", self.handle_delete)
        self.add_subcommand(
            "close",
            "Mine the current session into a new experience",
            self.handle_close,
        )
        self.add_subcommand("count", "Show total number of experiences", self.handle_count)

    # ------------------------------------------------------------------
    # Subcommand handlers
    # ------------------------------------------------------------------

    def handle_no_args(self) -> bool:
        """Default: show count + a short summary table of recent experiences."""
        try:
            from kryon.learning import count_experiences, list_experiences
        except Exception as e:
            console.print(f"[red]Learning module unavailable: {e}[/red]")
            return False

        total = count_experiences()
        console.print(
            Panel(
                f"[bold cyan]KRYON Experience Store[/bold cyan]\n"
                f"Total experiences: [bold green]{total}[/bold green]\n\n"
                "Subcommands: list | show <id> | search <text> | delete <id> | close [summary] | count",
                title="/experiences",
                border_style="cyan",
            )
        )
        if total > 0:
            return self.handle_list(["10"])
        else:
            console.print(
                "[dim]No experiences yet. Run some engagements and call "
                "[bold]/experiences close[/bold] at the end to start learning.[/dim]"
            )
            return True

    def handle_count(self, args: Optional[list[str]] = None) -> bool:
        from kryon.learning import count_experiences

        console.print(f"Total experiences: [bold green]{count_experiences()}[/bold green]")
        return True

    def handle_list(self, args: Optional[list[str]] = None) -> bool:
        try:
            from kryon.learning import list_experiences
        except Exception as e:
            console.print(f"[red]Learning module unavailable: {e}[/red]")
            return False

        limit = 10
        if args:
            try:
                limit = int(args[0])
            except ValueError:
                pass

        rows = list_experiences(limit=limit)
        if not rows:
            console.print("[yellow]No experiences stored yet.[/yellow]")
            return True

        table = Table(title=f"Last {len(rows)} experiences", show_lines=False)
        table.add_column("id", style="cyan", no_wrap=True)
        table.add_column("created", style="dim")
        table.add_column("host", style="magenta")
        table.add_column("outcome", style="bold")
        table.add_column("chain", justify="right")
        table.add_column("summary", style="white", overflow="fold")

        for r in rows:
            summary = (r.get("summary") or "")[:90]
            table.add_row(
                str(r.get("id") or "")[:16],
                (r.get("created_at") or "")[:19],
                (r.get("target_profile") or {}).get("host", "") or "",
                r.get("outcome") or "",
                str(len(r.get("chain") or [])),
                summary,
            )
        console.print(table)
        return True

    def handle_show(self, args: Optional[list[str]] = None) -> bool:
        if not args:
            console.print("[red]Usage: /experiences show <id>[/red]")
            return False

        try:
            from kryon.learning import get_experience
        except Exception as e:
            console.print(f"[red]Learning module unavailable: {e}[/red]")
            return False

        exp = get_experience(args[0])
        if not exp:
            console.print(f"[yellow]No experience with id '{args[0]}'[/yellow]")
            return True

        body = json.dumps(
            {k: v for k, v in exp.items() if k != "document"},
            indent=2,
            ensure_ascii=False,
        )
        console.print(
            Panel(body, title=f"Experience {exp.get('id')}", border_style="cyan")
        )
        return True

    def handle_search(self, args: Optional[list[str]] = None) -> bool:
        if not args:
            console.print("[red]Usage: /experiences search <free text query>[/red]")
            return False

        try:
            from kryon.learning import recall_similar
        except Exception as e:
            console.print(f"[red]Learning module unavailable: {e}[/red]")
            return False

        query = " ".join(args)
        hits = recall_similar(query, k=5)
        if not hits:
            console.print("[yellow]No matching experiences.[/yellow]")
            return True

        table = Table(title=f"Similarity search: {query}", show_lines=False)
        table.add_column("score", justify="right")
        table.add_column("id", style="cyan", no_wrap=True)
        table.add_column("host", style="magenta")
        table.add_column("outcome", style="bold")
        table.add_column("summary", overflow="fold")
        for h in hits:
            table.add_row(
                f"{h.get('score', 0):.3f}",
                str(h.get("id") or "")[:16],
                (h.get("target_profile") or {}).get("host", "") or "",
                h.get("outcome") or "",
                (h.get("summary") or "")[:90],
            )
        console.print(table)
        return True

    def handle_delete(self, args: Optional[list[str]] = None) -> bool:
        if not args:
            console.print("[red]Usage: /experiences delete <id>[/red]")
            return False

        try:
            from kryon.learning import delete_experience
        except Exception as e:
            console.print(f"[red]Learning module unavailable: {e}[/red]")
            return False

        ok = delete_experience(args[0])
        if ok:
            console.print(f"[green]Deleted experience {args[0]}[/green]")
        else:
            console.print(f"[yellow]No experience with id '{args[0]}'[/yellow]")
        return True

    def handle_close(self, args: Optional[list[str]] = None) -> bool:
        """Walk the current agent histories, extract the chain, build a
        profile, and persist one experience record."""

        try:
            from kryon.learning import (
                add_experience,
                build_profile,
                extract_chain_from_history,
            )
        except Exception as e:
            console.print(f"[red]Learning module unavailable: {e}[/red]")
            return False

        user_summary = " ".join(args) if args else ""

        histories = get_all_agent_histories() or {}
        if not histories:
            console.print(
                "[yellow]No active agent histories. Nothing to close.[/yellow]"
            )
            return True

        # Flatten all histories into a single message stream, keep the
        # agent_path for metadata. In practice REPL sessions touch one
        # or two agents so this is cheap.
        agent_path: list[str] = []
        merged_history: list[Any] = []
        for agent_name, hist in histories.items():
            if not hist:
                continue
            agent_path.append(agent_name)
            merged_history.extend(hist)

        if not merged_history:
            console.print("[yellow]Agent history is empty. Nothing to store.[/yellow]")
            return True

        chain_data = extract_chain_from_history(merged_history, agent_path=agent_path)

        # Build profile from whatever we can see
        tool_outputs = [c.get("output", "") for c in chain_data.get("chain", []) if c.get("output")]
        profile = build_profile(history=merged_history, tool_outputs=tool_outputs)

        if not profile.get("host") and not profile.get("resolved_ip"):
            console.print(
                "[yellow]Could not identify a target in this session. "
                "Experience not saved. Run at least one recon tool first.[/yellow]"
            )
            return True

        experience = {
            "target_profile": profile,
            "chain": chain_data["chain"],
            "outcome": chain_data["outcome"],
            "outcome_signals": chain_data["outcome_signals"],
            "agent_path": chain_data["agent_path"],
            "summary": user_summary or chain_data["summary"],
        }

        try:
            exp_id = add_experience(experience)
        except Exception as e:
            console.print(f"[red]Failed to store experience: {e}[/red]")
            return False

        console.print(
            Panel(
                f"[bold green]Experience stored[/bold green]\n"
                f"[cyan]id[/cyan]:       {exp_id}\n"
                f"[cyan]host[/cyan]:     {profile.get('host') or profile.get('resolved_ip')}\n"
                f"[cyan]ports[/cyan]:    {profile.get('ports') or []}\n"
                f"[cyan]tech[/cyan]:     {profile.get('tech') or []}\n"
                f"[cyan]outcome[/cyan]:  {chain_data['outcome']}\n"
                f"[cyan]chain[/cyan]:    {len(chain_data['chain'])} steps\n"
                f"[cyan]agents[/cyan]:   {', '.join(chain_data['agent_path'])}\n\n"
                f"[dim]Use /experiences list to verify.[/dim]",
                title="/experiences close",
                border_style="green",
            )
        )
        return True


register_command(ExperiencesCommand())


# ---------------------------------------------------------------------------
# Standalone function — reusable from auto_extract and the command handler
# ---------------------------------------------------------------------------

_already_closed = False


def close_and_save_experience(user_summary: str = "") -> tuple[bool, str | None]:
    """Mine current agent histories into an experience record.

    Returns (success, experience_id | None). Sets a module-level flag so
    auto-extract on exit won't duplicate a manual /experiences close.
    """
    global _already_closed

    from kryon.learning import add_experience, build_profile, extract_chain_from_history

    histories = get_all_agent_histories() or {}
    if not histories:
        return False, None

    agent_path: list[str] = []
    merged: list[Any] = []
    for name, hist in histories.items():
        if not hist:
            continue
        agent_path.append(name)
        merged.extend(hist)

    if not merged:
        return False, None

    # Must have at least one tool result to be worth saving
    if not any(m.get("role") == "tool" for m in merged):
        return False, None

    chain_data = extract_chain_from_history(merged, agent_path=agent_path)
    tool_outputs = [c.get("output", "") for c in chain_data.get("chain", []) if c.get("output")]
    profile = build_profile(history=merged, tool_outputs=tool_outputs)

    if not profile.get("host") and not profile.get("resolved_ip"):
        return False, None

    experience = {
        "target_profile": profile,
        "chain": chain_data["chain"],
        "outcome": chain_data["outcome"],
        "outcome_signals": chain_data["outcome_signals"],
        "agent_path": chain_data["agent_path"],
        "summary": user_summary or chain_data["summary"],
    }

    exp_id = add_experience(experience)
    _already_closed = True
    return True, exp_id


def was_already_closed() -> bool:
    """Check if /experiences close was already called this session."""
    return _already_closed
