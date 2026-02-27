"""
Activity spinner for agent processing.

Shows a rich.status.Status spinner while the agent is thinking,
providing visual feedback including elapsed time, tool calls,
and agent handoffs.
"""

import functools
import threading
import time

from rich.console import Console
from rich.status import Status

_SENTINEL = object()


class AgentSpinner:
    """Thread-safe spinner that shows agent activity during processing.

    Features:
    - Animated elapsed time counter (updates every 0.5s)
    - Tool call indication (``recon_scout is calling nmap_scan... (8s)``)
    - Handoff tracking (``recon_scout -> exploit_dev is thinking... (12s)``)
    - LLM turn counter showing progress across API round-trips
    - Non-blocking ``request_stop()`` safe for async contexts

    Usage::

        spinner = AgentSpinner("recon_scout", console)
        hooks = spinner.create_hooks()
        spinner.patch_model(agent.model)
        with spinner:
            asyncio.run(Runner.run(agent, input, hooks=hooks))
    """

    def __init__(self, agent_name: str, console: Console):
        self._agent_name = agent_name
        self._console = console
        self._status: Status | None = None
        self._thread: threading.Thread | None = None
        self._started = threading.Event()
        self._stop_event = threading.Event()
        self._start_time: float = 0
        self._tool_name: str | None = None
        self._handoff_agent: str | None = None
        self._tools_run: list[str] = []
        self._llm_turn: int = 0
        self._lock = threading.Lock()
        self._patched_models: list[tuple] = []  # (model, original_get_response)

    # ------------------------------------------------------------------
    # Message formatting
    # ------------------------------------------------------------------

    @staticmethod
    def _format_elapsed(seconds: float) -> str:
        minutes, secs = divmod(int(seconds), 60)
        if minutes > 0:
            return f"{minutes}m {secs}s"
        return f"{secs}s"

    def _build_message(self) -> str:
        parts: list[str] = [f"[bold cyan]{self._agent_name}[/bold cyan]"]

        if self._handoff_agent:
            parts.append(f"-> [bold yellow]{self._handoff_agent}[/bold yellow]")

        if self._tool_name:
            parts.append(f"is calling [bold green]{self._tool_name}[/bold green]...")
        elif self._llm_turn > 1:
            parts.append(f"is thinking... [dim](turn {self._llm_turn})[/dim]")
        else:
            parts.append("is thinking...")

        # Show recent tool history when back to thinking
        if not self._tool_name and self._tools_run:
            recent = self._tools_run[-3:]  # Last 3 tools
            parts.append(f"[dim]| ran: {', '.join(recent)}[/dim]")

        elapsed = time.time() - self._start_time
        elapsed_str = self._format_elapsed(elapsed)
        if elapsed >= 120:
            parts.append(f"[bold red]({elapsed_str} - Ctrl+C to cancel)[/bold red]")
        else:
            parts.append(f"[dim]({elapsed_str})[/dim]")

        return " ".join(parts)

    # ------------------------------------------------------------------
    # Background thread
    # ------------------------------------------------------------------

    def _run(self) -> None:
        self._start_time = time.time()
        self._status = Status(
            self._build_message(),
            console=self._console,
            spinner="dots",
        )
        self._status.start()
        self._started.set()

        while not self._stop_event.is_set():
            with self._lock:
                msg = self._build_message()
            self._status.update(msg)
            self._stop_event.wait(0.5)

        self._status.stop()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._started.wait()

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop_event.set()
        self._thread.join(timeout=1)
        self._thread = None
        self._status = None
        # Restore patched models
        for model, original in self._patched_models:
            model.get_response = original
        self._patched_models.clear()

    def request_stop(self) -> None:
        """Signal stop without blocking -- safe from async context."""
        self._stop_event.set()

    def update(
        self,
        *,
        tool_name: object = _SENTINEL,
        handoff_agent: object = _SENTINEL,
    ) -> None:
        """Update spinner state.  Pass ``None`` to clear a field."""
        with self._lock:
            if tool_name is not _SENTINEL:
                self._tool_name = tool_name  # type: ignore[assignment]
            if handoff_agent is not _SENTINEL:
                self._handoff_agent = handoff_agent  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Model patching — intercept get_response to track LLM turns
    # ------------------------------------------------------------------

    def patch_model(self, model) -> None:
        """Wrap model.get_response() to track LLM API call turns."""
        if not hasattr(model, "get_response"):
            return
        original = model.get_response
        spinner = self

        @functools.wraps(original)
        async def wrapped(*args, **kwargs):
            with spinner._lock:
                spinner._llm_turn += 1
            try:
                return await original(*args, **kwargs)
            finally:
                pass  # turn stays incremented

        model.get_response = wrapped
        self._patched_models.append((model, original))

    # ------------------------------------------------------------------
    # Hooks factory
    # ------------------------------------------------------------------

    def create_hooks(self):
        """Create RunHooks that update this spinner on tool/handoff events."""
        from kryon.sdk.agents.lifecycle import RunHooks

        spinner = self

        class SpinnerRunHooks(RunHooks):
            async def on_tool_start(self, context, agent, tool):
                name = getattr(tool, "name", None) or str(tool)
                spinner.update(tool_name=name)

            async def on_tool_end(self, context, agent, tool, result):
                name = getattr(tool, "name", None) or str(tool)
                with spinner._lock:
                    spinner._tools_run.append(name)
                    spinner._tool_name = None

            async def on_handoff(self, context, from_agent, to_agent):
                to_name = getattr(to_agent, "name", None) or str(to_agent)
                spinner.update(handoff_agent=to_name)

        return SpinnerRunHooks()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "AgentSpinner":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
