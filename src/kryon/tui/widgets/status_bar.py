"""Status bar widget."""

from textual.reactive import reactive
from textual.widgets import Static


class StatusBar(Static):
    """Shows current agent name, model, and status."""

    DEFAULT_CSS = """
    StatusBar {
        height: 1;
        dock: bottom;
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
    }
    """

    agent_name: reactive[str] = reactive("—")
    status: reactive[str] = reactive("idle")

    def render(self) -> str:
        status_icon = "[green]Ready[/]" if self.status == "idle" else "[yellow]Running...[/]"
        return f" Agent: [bold]{self.agent_name}[/] | {status_icon}"
