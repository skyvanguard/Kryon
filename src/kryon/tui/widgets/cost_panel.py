"""Cost and usage display widget."""

from textual.reactive import reactive
from textual.widgets import Static


class CostPanel(Static):
    """Displays real-time cost, token, and turn information."""

    DEFAULT_CSS = """
    CostPanel {
        height: auto;
        padding: 0;
    }
    """

    cost: reactive[float] = reactive(0.0)
    tokens: reactive[int] = reactive(0)
    turns: reactive[int] = reactive(0)
    model: reactive[str] = reactive("—")

    def render(self) -> str:
        return (
            f"[bold]Cost[/]\n"
            f"  ${self.cost:.6f}\n"
            f"[bold]Tokens[/]\n"
            f"  {self.tokens:,}\n"
            f"[bold]Turns[/]\n"
            f"  {self.turns}\n"
            f"[bold]Model[/]\n"
            f"  {self.model}"
        )
