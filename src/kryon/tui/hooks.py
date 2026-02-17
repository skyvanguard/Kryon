"""TUI-specific RunHooks that update widgets in real-time."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from kryon.sdk.agents.lifecycle import RunHooks

if TYPE_CHECKING:
    from kryon.sdk.agents.agent import Agent
    from kryon.sdk.agents.run_context import RunContextWrapper
    from kryon.sdk.agents.tool import Tool

    from kryon.tui.app import KryonTUI


class TUIRunHooks(RunHooks):
    """RunHooks implementation that pushes events to TUI widgets."""

    def __init__(self, app: KryonTUI) -> None:
        self._app = app

    async def on_agent_start(self, context: RunContextWrapper, agent: Agent) -> None:
        self._app.call_from_thread(self._app._on_agent_start, agent.name)

    async def on_agent_end(self, context: RunContextWrapper, agent: Agent, output: Any) -> None:
        self._app.call_from_thread(self._app._on_agent_end, output)

    async def on_tool_start(self, context: RunContextWrapper, agent: Agent, tool: Tool) -> None:
        self._app.call_from_thread(self._app._on_tool_start, tool.name)

    async def on_tool_end(self, context: RunContextWrapper, agent: Agent, tool: Tool, result: str) -> None:
        self._app.call_from_thread(self._app._on_tool_end, tool.name, result)

    async def on_handoff(self, context: RunContextWrapper, from_agent: Agent, to_agent: Agent) -> None:
        self._app.call_from_thread(self._app._on_handoff, from_agent.name, to_agent.name)
