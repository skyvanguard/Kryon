"""Chat panel widget using RichLog."""

from textual.widgets import RichLog


class ChatPanel(RichLog):
    """Scrollable chat log showing user and agent messages."""

    DEFAULT_CSS = """
    ChatPanel {
        height: 1fr;
        border: none;
        padding: 0 1;
    }
    """

    def add_user_message(self, text: str) -> None:
        self.write(f"[bold cyan]You:[/] {text}")

    def add_agent_message(self, text: str, agent_name: str = "Agent") -> None:
        self.write(f"[bold green]{agent_name}:[/] {text}")

    def add_system_message(self, text: str) -> None:
        self.write(f"[dim]{text}[/]")
