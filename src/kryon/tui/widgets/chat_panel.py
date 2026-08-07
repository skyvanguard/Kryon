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

    def __init__(self, **kwargs) -> None:
        # RichLog defaults to markup=False, which printed the `[bold cyan]…[/]`
        # tags literally. Enable markup + wrapping so messages render styled.
        kwargs.setdefault("markup", True)
        kwargs.setdefault("wrap", True)
        super().__init__(**kwargs)

    def add_user_message(self, text: str) -> None:
        self.write(f"[bold cyan]You:[/] {text}")

    def add_agent_message(self, text: str, agent_name: str = "Agent") -> None:
        self.write(f"[bold green]{agent_name}:[/] {text}")

    def add_system_message(self, text: str) -> None:
        self.write(f"[dim]{text}[/]")
