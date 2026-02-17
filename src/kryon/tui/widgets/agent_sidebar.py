"""Agent sidebar widget for selecting agents."""

from __future__ import annotations

from textual import on
from textual.message import Message
from textual.widgets import OptionList
from textual.widgets.option_list import Option


class AgentSidebar(OptionList):
    """Sidebar listing available agents."""

    DEFAULT_CSS = """
    AgentSidebar {
        height: 1fr;
        width: 100%;
        border: none;
    }
    """

    class AgentSelected(Message):
        """Fired when user selects an agent."""

        def __init__(self, agent_key: str) -> None:
            self.agent_key = agent_key
            super().__init__()

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._agent_keys: list[str] = []

    def populate(self, agents: dict) -> None:
        """Fill the sidebar with agent names."""
        self.clear_options()
        self._agent_keys = []
        for key in sorted(agents.keys()):
            agent = agents[key]
            name = getattr(agent, "name", key)
            self.add_option(Option(name, id=key))
            self._agent_keys.append(key)

    @on(OptionList.OptionSelected)
    def _on_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.post_message(self.AgentSelected(event.option.id))
