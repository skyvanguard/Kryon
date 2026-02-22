"""Tool call log panel."""

from textual.widgets import RichLog


class LogPanel(RichLog):
    """Displays tool call logs and events."""

    DEFAULT_CSS = """
    LogPanel {
        height: 1fr;
        border: none;
        padding: 0;
    }
    """

    def add_tool_call(self, tool_name: str, status: str = "running") -> None:
        icon = "[yellow]...[/]" if status == "running" else "[green]OK[/]"
        self.write(f"{icon} [bold]{tool_name}[/]")

    def add_tool_result(self, tool_name: str, result: str) -> None:
        short = result[:80].replace("\n", " ")
        self.write(f"  [dim]{short}[/]")

    def add_event(self, text: str) -> None:
        self.write(f"[dim]{text}[/]")
