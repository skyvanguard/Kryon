import functools
import json

# Configure logging for MCP operations
import logging
from typing import TYPE_CHECKING, Any

from .. import _debug
from ..exceptions import AgentsException, ModelBehaviorError, UserError
from ..logger import logger

mcp_logger = logging.getLogger("mcp.client")
if mcp_logger.level == logging.NOTSET:
    mcp_logger.setLevel(logging.WARNING)
from ..run_context import RunContextWrapper
from ..tool import FunctionTool, Tool
from ..tracing import FunctionSpanData, get_current_span, mcp_tools_span

if TYPE_CHECKING:
    from mcp.types import Tool as MCPTool

    from .server import MCPServer


class MCPUtil:
    """Set of utilities for interop between MCP and KRYON tools."""

    @classmethod
    async def get_all_function_tools(cls, servers: list["MCPServer"]) -> list[Tool]:
        """Get all function tools from a list of MCP servers."""
        tools = []
        tool_names: set[str] = set()
        for server in servers:
            server_tools = await cls.get_function_tools(server)
            server_tool_names = {tool.name for tool in server_tools}
            if len(server_tool_names & tool_names) > 0:
                raise UserError(f"Duplicate tool names found across MCP servers: {server_tool_names & tool_names}")
            tool_names.update(server_tool_names)
            tools.extend(server_tools)

        return tools

    @classmethod
    async def get_function_tools(cls, server: "MCPServer") -> list[Tool]:
        """Get all function tools from a single MCP server."""

        with mcp_tools_span(server=server.name) as span:
            tools = await server.list_tools()
            span.span_data.result = [tool.name for tool in tools]

        return [cls.to_function_tool(tool, server) for tool in tools]

    @classmethod
    def to_function_tool(cls, tool: "MCPTool", server: "MCPServer") -> FunctionTool:
        """Convert an MCP tool to a KRYON function tool.

        F85.C — Wrap the bare ``invoke_mcp_tool`` callable with the same
        failure-recovery shield that ``@function_tool`` ships by default
        (``default_tool_error_function``). Without this, an MCP server
        going down, a network blip, or a malformed JSON payload raised
        ``AgentsException`` / ``ModelBehaviorError`` that bubbled all
        the way to ``Runner.run`` and killed the engagement. With the
        shield, the error is returned to the LLM as a tool result so it
        can self-correct on the next turn — matching the behaviour for
        ``@function_tool``-decorated tools.
        """
        from kryon.sdk.agents.tool import default_tool_error_function

        raw_invoke = functools.partial(cls.invoke_mcp_tool, server, tool)

        async def _shielded_invoke(ctx: RunContextWrapper[Any], input_json: str) -> Any:
            try:
                return await raw_invoke(ctx, input_json)
            except Exception as exc:
                return default_tool_error_function(ctx, exc)

        return FunctionTool(
            name=tool.name,
            description=tool.description or "",
            params_json_schema=tool.inputSchema,
            on_invoke_tool=_shielded_invoke,
            strict_json_schema=False,
        )

    @classmethod
    async def invoke_mcp_tool(
        cls, server: "MCPServer", tool: "MCPTool", context: RunContextWrapper[Any], input_json: str
    ) -> str:
        """Invoke an MCP tool and return the result as a string."""
        try:
            json_data: dict[str, Any] = json.loads(input_json) if input_json else {}
        except Exception as e:
            if _debug.DONT_LOG_TOOL_DATA:
                logger.debug(f"Invalid JSON input for tool {tool.name}")
            else:
                logger.debug(f"Invalid JSON input for tool {tool.name}: {input_json}")
            raise ModelBehaviorError(f"Invalid JSON input for tool {tool.name}: {input_json}") from e

        if _debug.DONT_LOG_TOOL_DATA:
            logger.debug(f"Invoking MCP tool {tool.name}")
        else:
            logger.debug(f"Invoking MCP tool {tool.name} with input {input_json}")

        try:
            # Check if server session is still valid
            if not hasattr(server, "session") or server.session is None:
                logger.warning(f"MCP server session not found for tool {tool.name}, attempting to reconnect...")
                # Try to reconnect
                try:
                    await server.connect()
                    logger.info(f"Successfully reconnected to MCP server for tool {tool.name}")
                except Exception as reconnect_error:
                    logger.error(f"Failed to reconnect to MCP server: {reconnect_error}")
                    raise AgentsException(
                        f"MCP server connection lost for tool {tool.name}. "
                        f"Please remove and re-add the MCP server. "
                        f"Reconnection error: {str(reconnect_error)}"
                    ) from reconnect_error

            # Now try to call the tool
            result = await server.call_tool(tool.name, json_data)

        except AttributeError as ae:
            # This often happens when the server object is not properly initialized
            logger.error(f"MCP server not properly initialized for tool {tool.name}: {ae}")
            logger.error(f"Server type: {type(server)}, has session: {hasattr(server, 'session')}")
            raise AgentsException(
                f"MCP server not properly initialized for tool {tool.name}. "
                f"The server connection may have been lost. "
                f"AttributeError: {str(ae)}\n"
                f"Try: /mcp remove <server_name> then /mcp load ... to reconnect."
            ) from ae
        except Exception as e:
            # Log the full exception details
            logger.error(f"Error invoking MCP tool {tool.name}: {type(e).__name__}: {str(e)}")
            logger.error(f"Full exception details: {repr(e)}")

            # Check if it's a ClosedResourceError or connection issue
            error_type = type(e).__name__
            error_str = str(e).lower()

            # Also check for ExceptionGroup which wraps SSE errors
            if (
                error_type in ("ClosedResourceError", "ExceptionGroup")
                or "closedresourceerror" in error_str
                or "taskgroup" in error_str
            ):
                # Connection was closed, attempt to reconnect
                logger.debug(f"MCP connection issue for tool {tool.name}, attempting to reconnect...")
                try:
                    # Suppress warnings during reconnection
                    import warnings

                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=RuntimeWarning)
                        # Force reconnection. Use cleanup() (takes the server's
                        # _cleanup_lock and tears down the exit_stack) instead of poking
                        # server.session = None from outside the lock — the raw assignment
                        # raced concurrent call_tool/list_tools and could double-initialize.
                        await server.cleanup()
                        await server.connect()
                        logger.debug(f"Successfully reconnected to MCP server for tool {tool.name}")
                        # Retry the tool call
                        result = await server.call_tool(tool.name, json_data)
                        return await cls._format_tool_result(result, tool, server)
                except Exception as reconnect_error:
                    logger.debug(f"Failed to reconnect: {reconnect_error}")
                    raise AgentsException(
                        f"MCP server connection was closed and reconnection failed for tool {tool.name}. "
                        f"Please use '/mcp remove {server.name}' and '/mcp load ...' to reload the server."
                    ) from reconnect_error
            elif "session" in error_str or "connection" in error_str or "closed" in error_str:
                raise AgentsException(
                    f"MCP server connection error for tool {tool.name}. "
                    f"Error: {type(e).__name__}: {str(e)}\n"
                    f"Use '/mcp status' to check server health and '/mcp remove' + '/mcp load' to reconnect."
                ) from e
            else:
                # For other errors, include the full error details
                raise AgentsException(f"Error invoking MCP tool {tool.name}: {type(e).__name__}: {str(e)}") from e

        # Log and format the result
        return await cls._format_tool_result(result, tool, server)

    @classmethod
    async def _format_tool_result(cls, result, tool: "MCPTool", server: "MCPServer") -> str:
        """Format the MCP tool result into a string."""
        if _debug.DONT_LOG_TOOL_DATA:
            logger.debug(f"MCP tool {tool.name} completed.")
        else:
            logger.debug(f"MCP tool {tool.name} returned {result}")

        # MCP protocol: isError=True means the tool FAILED, even when it carries
        # content. The old code only treated empty content as an error, so a failed
        # tool's error message reached the model as a successful result — in an
        # offensive context the agent could read an exploit's error text as proof it
        # worked. Surface it explicitly as an error instead.
        if getattr(result, "isError", False):
            try:
                err = result.content[0].model_dump_json() if result.content else ""
            except Exception:  # noqa: BLE001
                err = str(getattr(result, "content", ""))
            logger.warning("MCP tool %s returned isError=True: %s", tool.name, err)
            return f"ERROR from MCP tool {tool.name}: {err or 'tool reported an error'}"

        # The MCP tool result is a list of content items, whereas OpenAI tool outputs are a single
        # string. We'll try to convert.
        if len(result.content) == 1:
            tool_output = result.content[0].model_dump_json()
        elif len(result.content) > 1:
            tool_output = json.dumps([item.model_dump() for item in result.content])
        else:
            logger.error(f"Errored MCP tool result: {result}")
            tool_output = "Error running tool."

        current_span = get_current_span()
        if current_span:
            if isinstance(current_span.span_data, FunctionSpanData):
                current_span.span_data.output = tool_output
                current_span.span_data.mcp_data = {
                    "server": server.name,
                }
            else:
                logger.warning(f"Current span is not a FunctionSpanData, skipping tool output: {current_span}")

        return tool_output
