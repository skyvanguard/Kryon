"""ConsoleSink — renders AgentEvents to a Rich console, reproducing the REPL's
existing look.

This proves the event protocol (``services.agent_events``) captures everything
the REPL shows today: it drives the SAME ``tool_call_renderer`` + finding-flash +
``◇ Kryon`` markdown the REPL already uses — but from events instead of inline
prints. When the turn-service (step 3) emits events, the REPL swaps its inline
rendering for this sink with zero visual change, and the SSE server emits the
identical events to the Go/Charm TUI. One producer, three renderers, no drift.
"""

from __future__ import annotations

from rich.console import Console
from rich.markdown import Markdown

from kryon.services.agent_events import AgentEvent, EventKind, SequencingSink


class ConsoleSink(SequencingSink):
    """Sink that renders each event to a Rich console. Rendering is best-effort —
    a bad event never breaks the turn (mirrors the REPL's fail-soft renderers)."""

    def __init__(self, console: Console | None = None) -> None:
        super().__init__()
        self.console = console or Console()

    def _emit(self, event: AgentEvent) -> None:
        try:
            self._dispatch(event)
        except Exception:  # noqa: BLE001 — render must never break the turn
            pass

    def _dispatch(self, event: AgentEvent) -> None:
        k = event.kind
        p = event.payload

        if k == EventKind.TOOL_STARTED:
            from kryon.repl.ui.tool_call_renderer import render_tool_invocation

            render_tool_invocation(
                tool_name=p.get("tool", "tool"),
                args_summary=p.get("args_summary", ""),
                console=self.console,
            )

        elif k == EventKind.TOOL_OUTPUT:
            from kryon.repl.ui.tool_call_renderer import render_tool_completion

            render_tool_completion(
                tool_name=p.get("tool", "tool"),
                duration_s=p.get("duration_s", 0.0),
                status=p.get("status", "ok"),
                summary=p.get("summary", ""),
                output=p.get("output", ""),
                console=self.console,
                step_id=p.get("step_id"),
            )

        elif k == EventKind.FINDING:
            from kryon.repl.ui.tool_call_renderer import render_finding_flash

            render_finding_flash(
                severity=p.get("severity", "INFO"),
                detail=p.get("detail", ""),
                console=self.console,
            )

        elif k == EventKind.ASSISTANT:
            md = p.get("markdown", "")
            if md.strip():
                # Same sello + Markdown as the REPL's non-streaming close path.
                self.console.print("[bold #45e0ef]◇ Kryon[/]")
                self.console.print(Markdown(md))

        elif k == EventKind.THINKING:
            txt = p.get("text", "")
            if txt.strip():
                self.console.print(f"[dim]{txt}[/dim]")

        elif k == EventKind.ENGINE_PHASE:
            note = p.get("note", "")
            if note:
                self.console.print(f"[dim #45e0ef]◆[/] [dim]{note}[/dim]")

        elif k == EventKind.PRE_HOOK:
            self.console.print(f"[dim cyan]▸[/dim cyan] [cyan]{p.get('name', '')}[/cyan]")

        elif k == EventKind.REFLECTION:
            note = p.get("note", "")
            if note:
                self.console.print(f"[dim cyan]🪞 {note}[/dim cyan]")

        elif k == EventKind.DONE:
            report = p.get("report_markdown", "")
            if report.strip():
                self.console.print(Markdown(report))

        elif k == EventKind.ERROR:
            self.console.print(f"[red]⚠ {p.get('message', '')}[/red]")

        # TURN_START / TURN_END carry no visual here — the REPL's crystalline Rule
        # separator already marks turn boundaries.


__all__ = ["ConsoleSink"]
