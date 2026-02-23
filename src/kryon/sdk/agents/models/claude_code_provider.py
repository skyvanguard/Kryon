"""
Claude Code CLI Provider for KRYON.

This provider allows KRYON to use Claude Code CLI as its LLM backend,
leveraging your Claude Pro Max subscription instead of separate API keys.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from openai.types.responses import (
    Response,
    ResponseCompletedEvent,
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from ..items import ModelResponse, TResponseInputItem, TResponseOutputItem, TResponseStreamEvent
from ..tool import FunctionTool, Tool
from ..usage import Usage
from .interface import Model, ModelProvider, ModelTracing

if TYPE_CHECKING:
    from ..agent_output import AgentOutputSchema
    from ..handoffs import Handoff
    from ..model_settings import ModelSettings


@dataclass
class ClaudeCodeConfig:
    """Configuration for Claude Code CLI integration."""

    model: str = "sonnet"  # sonnet, opus, haiku
    timeout: int = 300  # seconds
    max_budget_usd: float | None = None
    extra_args: list[str] | None = None


class ClaudeCodeModel(Model):
    """
    Model implementation that uses Claude Code CLI as the backend.

    This allows KRYON to leverage your Claude Pro Max subscription
    instead of requiring separate API keys.
    """

    def __init__(
        self,
        model: str = "sonnet",
        timeout: int = 300,
        max_budget_usd: float | None = None,
    ):
        self.model = model
        self.timeout = timeout
        self.max_budget_usd = max_budget_usd

    def _format_messages_as_prompt(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        tools: list[Tool],
    ) -> str:
        """Convert KRYON message format to a prompt string for Claude Code CLI."""
        parts = []

        # Add system instructions
        if system_instructions:
            parts.append(f"<system>\n{system_instructions}\n</system>\n")

        # Add tool descriptions if any
        if tools:
            tool_descriptions = []
            for tool in tools:
                if isinstance(tool, FunctionTool):
                    desc = f"- {tool.name}: {tool.description}"
                    if tool.params_json_schema:
                        desc += f"\n  Parameters: {json.dumps(tool.params_json_schema)}"
                    tool_descriptions.append(desc)

            if tool_descriptions:
                parts.append("<available_tools>\n" + "\n".join(tool_descriptions) + "\n</available_tools>\n")
                parts.append(
                    "<tool_use_instructions>\n"
                    "To use a tool, respond with JSON in this format:\n"
                    '{"tool_call": {"name": "tool_name", "arguments": {...}}}\n'
                    "After the tool result, continue your response.\n"
                    "</tool_use_instructions>\n"
                )

        # Add conversation history
        if isinstance(input, str):
            parts.append(f"<user>\n{input}\n</user>")
        else:
            for item in input:
                if isinstance(item, dict):
                    role = item.get("role", "user")
                    content = item.get("content", "")
                    if isinstance(content, list):
                        # Handle multi-part content
                        text_parts = []
                        for part in content:
                            if isinstance(part, dict) and part.get("type") == "input_text":
                                text_parts.append(part.get("text", ""))
                            elif isinstance(part, dict) and part.get("type") == "output_text":
                                text_parts.append(part.get("text", ""))
                        content = "\n".join(text_parts)
                    parts.append(f"<{role}>\n{content}\n</{role}>")

        return "\n".join(parts)

    def _parse_tool_calls(self, text: str) -> tuple[str, list[dict]]:
        """
        Parse tool calls from Claude's response.
        Returns (cleaned_text, tool_calls).
        """
        tool_calls = []
        # Look for JSON tool call patterns
        import re

        pattern = r'\{"tool_call":\s*\{[^}]+\}\}'

        matches = re.findall(pattern, text, re.DOTALL)
        for match in matches:
            try:
                parsed = json.loads(match)
                if "tool_call" in parsed:
                    tool_calls.append(parsed["tool_call"])
            except json.JSONDecodeError:
                pass

        # Remove tool call JSON from text
        cleaned_text = re.sub(pattern, "", text).strip()
        return cleaned_text, tool_calls

    async def _run_claude_cli(self, prompt: str) -> dict[str, Any]:
        """Execute Claude Code CLI and return the response."""
        cmd = [
            "claude",
            "-p",
            "--output-format",
            "json",
            "--model",
            self.model,
        ]

        if self.max_budget_usd:
            cmd.extend(["--max-budget-usd", str(self.max_budget_usd)])

        # Run in subprocess
        loop = asyncio.get_event_loop()

        def run_subprocess():
            try:
                result = subprocess.run(
                    cmd,
                    input=prompt,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    encoding="utf-8",
                )
                return result.stdout, result.stderr, result.returncode
            except subprocess.TimeoutExpired:
                return "", "Timeout expired", -1
            except Exception as e:
                return "", str(e), -1

        stdout, stderr, returncode = await loop.run_in_executor(None, run_subprocess)

        if returncode != 0:
            raise RuntimeError(f"Claude Code CLI failed: {stderr}")

        # Parse JSON response
        try:
            response = json.loads(stdout)
            return response
        except json.JSONDecodeError:
            # If not valid JSON, treat as plain text response
            return {"result": stdout, "is_error": False}

    async def get_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchema | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
    ) -> ModelResponse:
        """Get a response from Claude Code CLI."""
        prompt = self._format_messages_as_prompt(system_instructions, input, tools)

        response_data = await self._run_claude_cli(prompt)

        # Extract text content from response
        if isinstance(response_data, dict):
            text = response_data.get("result", response_data.get("content", str(response_data)))
        else:
            text = str(response_data)

        # Print the response (KRYON CLI expects the model to print its output)
        if text:
            from rich.console import Console
            from rich.markdown import Markdown
            from rich.panel import Panel

            console = Console()
            md = Markdown(text)
            console.print(Panel(md, title="🤖 Claude", border_style="cyan"))

        # Parse any tool calls
        cleaned_text, tool_calls = self._parse_tool_calls(text)

        # Build output items
        output: list[TResponseOutputItem] = []

        # Add tool calls if any
        for _i, tc in enumerate(tool_calls):
            output.append(
                ResponseFunctionToolCall(
                    type="function_call",
                    id=f"call_{uuid.uuid4().hex[:8]}",
                    call_id=f"call_{uuid.uuid4().hex[:8]}",
                    name=tc.get("name", ""),
                    arguments=json.dumps(tc.get("arguments", {})),
                )
            )

        # Add text message if there's content
        if cleaned_text:
            output.append(
                ResponseOutputMessage(
                    type="message",
                    id=f"msg_{uuid.uuid4().hex[:8]}",
                    role="assistant",
                    content=[ResponseOutputText(type="output_text", text=cleaned_text, annotations=[])],
                    status="completed",
                )
            )

        return ModelResponse(
            output=output,
            usage=Usage(),  # Claude Code CLI doesn't expose token counts easily
            referenceable_id=None,
        )

    async def stream_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchema | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
    ) -> AsyncIterator[TResponseStreamEvent]:
        """Stream response from Claude Code CLI."""
        # For now, we don't support true streaming - we get the full response
        # and emit it as a completed event
        response = await self.get_response(
            system_instructions,
            input,
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
        )

        yield ResponseCompletedEvent(
            type="response.completed",
            response=Response(
                id=f"resp_{uuid.uuid4().hex[:8]}",
                created_at=0,
                model=self.model,
                object="response",
                output=response.output,
                tool_choice="auto",
                tools=[],
                top_p=None,
                parallel_tool_calls=False,
            ),
            sequence_number=0,
        )


class ClaudeCodeProvider(ModelProvider):
    """
    Model provider that uses Claude Code CLI.

    Usage:
        from kryon.sdk.agents import Runner, RunConfig
        from kryon.sdk.agents.models.claude_code_provider import ClaudeCodeProvider

        config = RunConfig(model_provider=ClaudeCodeProvider())
        result = await Runner.run(agent, "Your prompt", run_config=config)
    """

    def __init__(
        self,
        default_model: str = "sonnet",
        timeout: int = 300,
        max_budget_usd: float | None = None,
    ):
        self.default_model = default_model
        self.timeout = timeout
        self.max_budget_usd = max_budget_usd

    def get_model(self, model_name: str | None) -> Model:
        """Get a Claude Code model instance."""
        model = model_name or self.default_model
        return ClaudeCodeModel(
            model=model,
            timeout=self.timeout,
            max_budget_usd=self.max_budget_usd,
        )
