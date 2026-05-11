"""F85.C — Failure recovery at the tool layer.

The ``@function_tool`` decorator already wraps callables with
``default_tool_error_function`` so tool exceptions become tool-result
strings the LLM can read. The two direct ``FunctionTool(...)`` call
sites (MCP server proxies in ``sdk.agents.mcp.util`` and
``repl.commands.mcp``) used to skip that wrapper — a single MCP
server going down crashed the whole engagement. F85.C adds an
equivalent shield around those raw callables.

The connection-layer retry added to ``openai_chatcompletions.py`` is
validated by visual inspection of the diff (the catch block is
side-by-side with the existing RateLimitError catch and uses the same
``await asyncio.sleep`` + ``continue`` pattern); writing an isolated
test for it requires fully constructing a model instance with its
litellm config and is best validated by an end-to-end smoke run.
"""

from __future__ import annotations

from typing import Any

import pytest


class _FakeMCPServer:
    """Minimal MCPServerBase stand-in. ``call_tool`` raises on demand."""

    name = "fake-mcp"

    def __init__(self, raises: Exception | None = None):
        self._raises = raises
        # truthy so the reconnect path inside invoke_mcp_tool is skipped
        self.session = object()

    async def call_tool(self, name: str, args: dict) -> Any:  # noqa: ARG002
        if self._raises is not None:
            raise self._raises
        return {"ok": True}


class _FakeMCPTool:
    name = "fake-tool"
    description = "fake"
    inputSchema = {"type": "object", "properties": {}}


@pytest.mark.asyncio
async def test_mcp_shield_converts_connection_error_to_string():
    """An MCP server raising ConnectionError must NOT propagate; the
    shield converts it to a string the LLM can read."""
    from kryon.sdk.agents.mcp.util import MCPUtil
    from kryon.sdk.agents.run_context import RunContextWrapper

    server = _FakeMCPServer(raises=ConnectionError("server gone"))
    tool = MCPUtil.to_function_tool(_FakeMCPTool(), server)  # type: ignore[arg-type]

    ctx = RunContextWrapper(context=None)
    out = await tool.on_invoke_tool(ctx, "{}")

    assert isinstance(out, str)
    assert "error" in out.lower()
    assert "server gone" in out


@pytest.mark.asyncio
async def test_mcp_shield_converts_timeout_to_string():
    from kryon.sdk.agents.mcp.util import MCPUtil
    from kryon.sdk.agents.run_context import RunContextWrapper

    server = _FakeMCPServer(raises=TimeoutError("call timed out"))
    tool = MCPUtil.to_function_tool(_FakeMCPTool(), server)  # type: ignore[arg-type]

    ctx = RunContextWrapper(context=None)
    out = await tool.on_invoke_tool(ctx, "{}")

    assert isinstance(out, str)
    assert "call timed out" in out


@pytest.mark.asyncio
async def test_mcp_shield_converts_value_error_to_string():
    """Tool-logic exceptions (ValueError from a buggy MCP server) also
    must convert to a string rather than killing the run."""
    from kryon.sdk.agents.mcp.util import MCPUtil
    from kryon.sdk.agents.run_context import RunContextWrapper

    server = _FakeMCPServer(raises=ValueError("invalid input"))
    tool = MCPUtil.to_function_tool(_FakeMCPTool(), server)  # type: ignore[arg-type]

    ctx = RunContextWrapper(context=None)
    out = await tool.on_invoke_tool(ctx, "{}")

    assert isinstance(out, str)
    assert "invalid input" in out


@pytest.mark.asyncio
async def test_mcp_shield_passes_through_success():
    """When the MCP server returns normally, the shield must not
    intercept — the tool result flows through unchanged. We model a
    real MCP CallToolResult shape (list of content items with
    ``.model_dump_json()``) so ``_format_tool_result`` succeeds."""
    from kryon.sdk.agents.mcp.util import MCPUtil
    from kryon.sdk.agents.run_context import RunContextWrapper

    class _FakeContent:
        def model_dump_json(self) -> str:
            return '{"type":"text","text":"hello"}'

        def model_dump(self) -> dict:
            return {"type": "text", "text": "hello"}

    class _FakeResult:
        content = [_FakeContent()]

    class _SuccessServer:
        name = "fake-mcp"
        session = object()

        async def call_tool(self, name: str, args: dict):  # noqa: ARG002
            return _FakeResult()

    tool = MCPUtil.to_function_tool(_FakeMCPTool(), _SuccessServer())  # type: ignore[arg-type]

    ctx = RunContextWrapper(context=None)
    out = await tool.on_invoke_tool(ctx, "{}")

    # Should be the JSON of the single content item, not an error string
    assert "hello" in out
    assert "error" not in out.lower()
