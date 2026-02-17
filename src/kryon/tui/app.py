"""KRYON Terminal UI application."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, Static

from kryon.tui.widgets.agent_sidebar import AgentSidebar
from kryon.tui.widgets.chat_panel import ChatPanel
from kryon.tui.widgets.cost_panel import CostPanel
from kryon.tui.widgets.log_panel import LogPanel
from kryon.tui.widgets.status_bar import StatusBar

CSS_PATH = Path(__file__).parent / "styles" / "kryon.tcss"


class KryonTUI(App):
    """Main Textual application for KRYON."""

    TITLE = "KRYON TUI"
    SUB_TITLE = "Autonomous Cybersecurity Intelligence Platform"
    CSS_PATH = CSS_PATH
    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
        ("ctrl+l", "clear_chat", "Clear"),
    ]

    def __init__(self, agent_key: str | None = None, model_override: str | None = None, **kwargs):
        super().__init__(**kwargs)
        self._agent_key = agent_key
        self._model_override = model_override
        self._current_agent: Any = None
        self._input_history: list = []
        self._agents: dict = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="agent-sidebar"):
                yield Static("Agents", classes="section-title")
                yield AgentSidebar(id="agent-list")
            with Vertical(id="chat-panel"):
                yield ChatPanel(id="chat")
            with Vertical(id="info-panel"):
                yield CostPanel(id="cost-display")
                yield Static("Tool Logs", classes="section-title")
                yield LogPanel(id="log-display")
        yield Input(placeholder="Type your message...", id="prompt-input")
        yield StatusBar(id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        """Initialize agents on mount."""
        from kryon.agents import get_available_agents, get_agent_by_name

        self._agents = get_available_agents()

        sidebar: AgentSidebar = self.query_one("#agent-list", AgentSidebar)
        sidebar.populate(self._agents)

        # Set initial agent
        key = self._agent_key or "recon_scout"
        if key not in self._agents:
            key = next(iter(self._agents))
        self._switch_agent(key)

        self.query_one("#prompt-input", Input).focus()

    def _switch_agent(self, agent_key: str) -> None:
        from kryon.agents import get_agent_by_name

        try:
            self._current_agent = get_agent_by_name(agent_key, model_override=self._model_override)
            self._agent_key = agent_key
            self._input_history = []

            status: StatusBar = self.query_one("#status-bar", StatusBar)
            status.agent_name = getattr(self._current_agent, "name", agent_key)

            cost: CostPanel = self.query_one("#cost-display", CostPanel)
            model = getattr(self._current_agent, "model", None)
            cost.model = getattr(model, "model", "—") if model else "—"

            chat: ChatPanel = self.query_one("#chat", ChatPanel)
            chat.add_system_message(f"Switched to {status.agent_name}")
        except ValueError as e:
            chat: ChatPanel = self.query_one("#chat", ChatPanel)
            chat.add_system_message(f"Error: {e}")

    @on(AgentSidebar.AgentSelected)
    def _on_agent_selected(self, event: AgentSidebar.AgentSelected) -> None:
        self._switch_agent(event.agent_key)

    @on(Input.Submitted, "#prompt-input")
    async def _on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        event.input.value = ""

        chat: ChatPanel = self.query_one("#chat", ChatPanel)
        chat.add_user_message(text)

        if self._current_agent is None:
            chat.add_system_message("No agent selected")
            return

        self._run_agent(text)

    @work(thread=True)
    def _run_agent(self, user_input: str) -> None:
        """Run the agent in a background thread."""
        import asyncio

        from kryon.sdk.agents import Runner

        status: StatusBar = self.query_one("#status-bar", StatusBar)
        self.call_from_thread(setattr, status, "status", "running")

        # Build input
        input_items: str | list = user_input
        if self._input_history:
            input_items = self._input_history + [{"role": "user", "content": user_input}]

        try:
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(
                Runner.run(self._current_agent, input=input_items, max_turns=10)
            )
            loop.close()

            output = result.final_output or ""
            agent_name = result.last_agent.name if result.last_agent else "Agent"

            # Update history
            self._input_history = list(result.to_input_list())

            # Update cost
            cost_panel: CostPanel = self.query_one("#cost-display", CostPanel)
            usage = result.raw_responses[-1].usage if result.raw_responses else None
            if usage:
                self.call_from_thread(setattr, cost_panel, "tokens", cost_panel.tokens + usage.total_tokens)
            self.call_from_thread(setattr, cost_panel, "turns", cost_panel.turns + 1)

            chat: ChatPanel = self.query_one("#chat", ChatPanel)
            self.call_from_thread(chat.add_agent_message, output, agent_name)

        except Exception as e:
            chat: ChatPanel = self.query_one("#chat", ChatPanel)
            self.call_from_thread(chat.add_system_message, f"Error: {e}")
        finally:
            self.call_from_thread(setattr, status, "status", "idle")

    # --- Callbacks for TUIRunHooks ---

    def _on_agent_start(self, agent_name: str) -> None:
        status: StatusBar = self.query_one("#status-bar", StatusBar)
        status.agent_name = agent_name

    def _on_agent_end(self, output: Any) -> None:
        pass  # Handled in _run_agent

    def _on_tool_start(self, tool_name: str) -> None:
        log: LogPanel = self.query_one("#log-display", LogPanel)
        log.add_tool_call(tool_name, "running")

    def _on_tool_end(self, tool_name: str, result: str) -> None:
        log: LogPanel = self.query_one("#log-display", LogPanel)
        log.add_tool_result(tool_name, result)

    def _on_handoff(self, from_name: str, to_name: str) -> None:
        log: LogPanel = self.query_one("#log-display", LogPanel)
        log.add_event(f"Handoff: {from_name} -> {to_name}")
        chat: ChatPanel = self.query_one("#chat", ChatPanel)
        chat.add_system_message(f"Handoff to {to_name}")

    def action_clear_chat(self) -> None:
        chat: ChatPanel = self.query_one("#chat", ChatPanel)
        chat.clear()
        log: LogPanel = self.query_one("#log-display", LogPanel)
        log.clear()
