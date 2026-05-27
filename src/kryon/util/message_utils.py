"""
Message utilities for KRYON.

This module provides functions for parsing, fixing, and displaying
messages in the agent communication system.
"""

import json
import os
import re
from datetime import datetime


def _hide_cost() -> bool:
    """Hide cost counters when running on local Ollama (always $0).
    Default: hidden. Set `KRYON_HIDE_COST=0` to show them again."""
    val = os.environ.get("KRYON_HIDE_COST", "1").strip().lower()
    return val in ("1", "true", "yes", "on")


from rich.box import ROUNDED
from rich.console import Console, Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from wasabi import color

from kryon.util.cost_tracker import (
    COST_TRACKER,
    format_time,
    get_model_input_tokens,
    get_model_name,
)

# Set up theme for console
theme = Theme(
    {
        "timestamp": "#00BCD4",
        "agent": "#4CAF50",
        "arrow": "#FFFFFF",
        "content": "#ECEFF1",
        "tool": "#F44336",
        "cost": "#009688",
        "args_str": "#FFC107",
        "border": "#2196F3",
        "border_state": "#FFD700",
        "model": "#673AB7",
        "dim": "#9E9E9E",
        "current_token_count": "#E0E0E0",
        "total_token_count": "#757575",
        "context_tokens": "#0A0A0A",
        "success": "#4CAF50",
        "warning": "#FF9800",
        "error": "#F44336",
    }
)

console = Console(theme=theme)


def fix_litellm_transcription_annotations():
    """
    Apply a monkey patch to fix the TranscriptionCreateParams.__annotations__ issue in LiteLLM.

    This is a temporary fix until the issue is fixed in the LiteLLM library itself.
    """
    try:
        import litellm.litellm_core_utils.model_param_helper as model_param_helper

        # Override the problematic method to avoid the error
        def safe_get_transcription_kwargs():
            """A safer version that doesn't rely on __annotations__."""
            return {
                "file",
                "model",
                "language",
                "prompt",
                "response_format",
                "temperature",
                "api_base",
                "api_key",
                "api_version",
                "timeout",
                "custom_llm_provider",
            }

        # Apply the monkey patch
        model_param_helper.ModelParamHelper._get_litellm_supported_transcription_kwargs = safe_get_transcription_kwargs
        return True
    except (ImportError, AttributeError):
        # If the import fails or the attribute doesn't exist, the patch couldn't be applied
        return False


def fix_message_list(messages):  # pylint: disable=R0914,R0915,R0912
    """
    Sanitizes the message list passed as a parameter to align with the
    OpenAI API message format.

    Adjusts the message list to comply with the following rules:
        1. A tool call id appears no more than twice.
        2. Each tool call id appears as a pair, and both messages
            must have content.
        3. If a tool call id appears alone (without a pair), it is removed.
        4. There cannot be empty messages.
        5. Each tool_use block (assistant with tool_calls) must be followed by
           a tool_result block (tool message with matching tool_call_id).
        6. Each 'tool' message must be immediately preceded by an 'assistant' message
           with matching tool_call_id in its tool_calls.
        7. Tool call IDs are truncated to 40 characters for API compatibility.

    Args:
        messages (List[dict]): List of message dictionaries containing
                            role, content, and optionally tool_calls or
                            tool_call_id fields.

    Returns:
        List[dict]: Sanitized list of messages with invalid tool calls
                   and empty messages removed.

    FASE 11.S — rewritten to O(n). The previous implementation used a
    while-loop with a nested ``enumerate`` linear search (~line 230)
    to locate the assistant matching each out-of-sequence tool
    message. On Bench Robots (2026-05-27) the engage main thread sat
    14+ minutes at 49% CPU inside that O(n²) hot path once the
    history accumulated nikto/whatweb/nuclei tool outputs plus the
    qwen3-8b-active reasoning blocks. The new algorithm builds the
    result in a single linear pass driven by pre-computed dicts.
    """
    # Stage 1: sanitize tool_call_id lengths (deep-copy to avoid
    # mutating caller's input).
    sanitized = []
    for msg in messages:
        msg_copy = msg.copy()
        if msg_copy.get("role") == "tool" and msg_copy.get("tool_call_id"):
            if len(msg_copy["tool_call_id"]) > 40:
                msg_copy["tool_call_id"] = msg_copy["tool_call_id"][:40]
        if msg_copy.get("role") == "assistant" and msg_copy.get("tool_calls"):
            tool_calls_copy = []
            for tc in msg_copy["tool_calls"]:
                tc_copy = tc.copy()
                if tc_copy.get("id") and len(tc_copy["id"]) > 40:
                    tc_copy["id"] = tc_copy["id"][:40]
                tool_calls_copy.append(tc_copy)
            msg_copy["tool_calls"] = tool_calls_copy
        sanitized.append(msg_copy)

    # Stage 2: drop empty user messages; keep empty system as "".
    # Track assistant messages by tool_id and queue tool responses
    # that arrive before their assistant by buffering them keyed on
    # tool_id. We DO NOT emit anything yet — first we need to know
    # which assistants exist so we can decide how to handle orphan
    # tool messages (and avoid the O(n²) "find assistant" search).
    cleaned = []
    for msg in sanitized:
        if msg.get("role") in ("user", "system") and (
            msg.get("content") is None or not str(msg.get("content", "")).strip()
        ):
            if msg.get("role") == "system":
                msg["content"] = ""
                cleaned.append(msg)
            # Empty user messages are dropped entirely (matches legacy).
            continue
        cleaned.append(msg)

    # Build an O(1) lookup: tool_id -> tool_name from any assistant
    # message that advertises that tool_call_id. Used to label
    # synthetic tool responses correctly when we have to insert one.
    assistant_tool_names = {}
    for msg in cleaned:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                tool_id = tc.get("id")
                if not tool_id:
                    continue
                fn = tc.get("function") or {}
                assistant_tool_names.setdefault(tool_id, fn.get("name") or "unknown_function")

    # Collect tool responses keyed by tool_id. If the same id appears
    # twice (LLM retry, replayed history), prefer the LAST one — same
    # tie-break as the legacy code, which updated tool_idx on each
    # encounter without dedup.
    tool_responses = {}
    for msg in cleaned:
        if msg.get("role") == "tool" and msg.get("tool_call_id"):
            tool_responses[msg["tool_call_id"]] = msg

    # Stage 3: emit the final list. For each non-tool message:
    #   - emit it as-is
    #   - if it's an assistant with tool_calls, immediately emit each
    #     matching tool response (consuming from tool_responses); if a
    #     tool_call has no response, synthesize one
    # For each tool message: skip — it has already been emitted with
    # its assistant. If the tool's id had no matching assistant
    # anywhere in the history, synthesize a stub assistant + emit the
    # tool message right after.
    final = []
    consumed_tool_ids = set()
    for msg in cleaned:
        role = msg.get("role")
        if role == "tool":
            tool_id = msg.get("tool_call_id")
            if tool_id in consumed_tool_ids:
                # Already attached to its assistant earlier.
                continue
            if tool_id not in assistant_tool_names:
                # Orphan tool — synthesize stub assistant + emit.
                stub_assistant = {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": tool_id,
                            "type": "function",
                            "function": {"name": "unknown_function", "arguments": "{}"},
                        }
                    ],
                }
                final.append(stub_assistant)
                final.append(msg)
                consumed_tool_ids.add(tool_id)
            # If assistant exists but we hit the tool first (out of
            # order), drop this stray — when we reach the assistant we
            # will re-emit a fresh copy from tool_responses keyed on
            # the same id. consumed_tool_ids stops re-emission later.
            continue

        final.append(msg)
        if role == "assistant" and msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                tool_id = tc.get("id")
                if not tool_id:
                    continue
                if tool_id in consumed_tool_ids:
                    continue
                tool_msg = tool_responses.get(tool_id)
                if tool_msg is None:
                    # Synthesize tool response for the call.
                    fn = tc.get("function") or {}
                    tool_name = fn.get("name") or "unknown_function"
                    tool_msg = {
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": f"Auto-generated response for {tool_name}",
                    }
                final.append(tool_msg)
                consumed_tool_ids.add(tool_id)

    # Stage 4: enforce non-null content where providers reject null,
    # and ensure tool messages always have non-empty content. Same
    # contract as the legacy code.
    for msg in final:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            # Assistant messages with tool calls may legitimately have
            # content=None; leave them alone.
            continue
        if msg.get("role") == "tool":
            if msg.get("content") is None or msg.get("content") == "":
                msg["content"] = f"Tool response for {msg.get('tool_call_id', 'unknown')}"
            continue
        if msg.get("content") is None and not msg.get("tool_calls"):
            msg["content"] = ""

    return final


def get_language_from_code_block(lang_identifier):
    """
    Maps a language identifier from a markdown code block to a proper syntax
    highlighting language name. Handles common aliases and defaults.

    Args:
        lang_identifier (str): Language identifier from markdown code block

    Returns:
        str: Proper language name for syntax highlighting
    """
    # Convert to lowercase and strip whitespace
    lang = lang_identifier.lower().strip() if lang_identifier else ""

    # Map common language aliases to their proper names
    lang_map = {
        # Empty strings or unknown
        "": "text",
        # Python variants
        "py": "python",
        "python3": "python",
        # JavaScript variants
        "js": "javascript",
        "jsx": "jsx",
        "ts": "typescript",
        "tsx": "tsx",
        "typescript": "typescript",
        # Shell variants
        "sh": "bash",
        "shell": "bash",
        "console": "bash",
        "terminal": "bash",
        # Web languages
        "html": "html",
        "css": "css",
        "json": "json",
        "xml": "xml",
        "yml": "yaml",
        "yaml": "yaml",
        # C family
        "c": "c",
        "cpp": "cpp",
        "c++": "cpp",
        "csharp": "csharp",
        "cs": "csharp",
        "java": "java",
        # Other common languages
        "go": "go",
        "golang": "go",
        "ruby": "ruby",
        "rb": "ruby",
        "rust": "rust",
        "php": "php",
        "sql": "sql",
        "diff": "diff",
        "markdown": "markdown",
        "md": "markdown",
        # Default fallback
        "text": "text",
        "plaintext": "text",
        "txt": "text",
    }

    # Return mapped language or default to the original if not in map
    return lang_map.get(lang, lang or "text")


def cli_print_tool_call(tool_name="", args="", output="", prefix="  "):
    """Print a tool call with pretty formatting"""
    if not tool_name:
        return

    print(f"{prefix}{color('Tool Call:', fg='cyan')}")
    print(f"{prefix}{color('Name:', fg='cyan')} {tool_name}")
    if args:
        print(f"{prefix}{color('Args:', fg='cyan')} {args}")
    if output:
        print(f"{prefix}{color('Output:', fg='cyan')} {output}")


def parse_message_content(message):
    """
    Parse a message object to extract its textual content.
    Only processes messages that don't have tool calls.
    Detects markdown code blocks and applies syntax highlighting in non-streaming mode.
    Also formats other markdown elements like headers, lists, and text formatting.

    Args:
        message: Can be a string or a Message object with content attribute

    Returns:
        str or rich.console.Group: The extracted content as a string or as a rich Group with Syntax highlighting
    """
    # Extract the raw content
    raw_content = ""

    # If message is already a string, use it
    if isinstance(message, str):
        raw_content = message
    # If message is a Message object with content attribute
    elif hasattr(message, "content") and message.content is not None:
        raw_content = message.content
    # If message is a dict with content key
    elif isinstance(message, dict) and "content" in message:
        raw_content = message["content"]
    # If we can't extract content, convert to string
    else:
        raw_content = str(message)

    # Check if streaming is enabled
    streaming_enabled = os.getenv("KRYON_STREAM", "false").lower() == "true"

    # Only apply markdown formatting in non-streaming mode
    if not streaming_enabled and raw_content:
        # Check if content contains markdown code blocks with improved regex
        code_block_pattern = r"```(\w*)\s*([\s\S]*?)\s*```"
        matches = re.findall(code_block_pattern, raw_content, re.DOTALL)

        if matches:
            # Prepare to process markdown with code blocks highlighted
            elements = []
            last_end = 0

            # Find all code blocks with improved regex pattern
            for match in re.finditer(r"```(\w*)\s*([\s\S]*?)\s*```", raw_content, re.DOTALL):
                # Get text before the code block
                start = match.start()
                if start > last_end:
                    text_before = raw_content[last_end:start]

                    # Process markdown in the text before the code block
                    if text_before.strip():
                        md = Markdown(text_before)
                        elements.append(md)

                # Process the code block
                lang = match.group(1) or "text"
                code = match.group(2)

                # Use the language mapping helper to get proper syntax highlighting
                syntax_lang = get_language_from_code_block(lang)

                # Create syntax highlighted code
                syntax = Syntax(
                    code,
                    syntax_lang,
                    theme="monokai",
                    line_numbers=True,
                    word_wrap=True,
                    background_color="#272822",
                )
                elements.append(syntax)

                last_end = match.end()

            # Add any remaining text after the last code block
            if last_end < len(raw_content):
                text_after = raw_content[last_end:]

                # Process markdown in the text after the code block
                if text_after.strip():
                    md = Markdown(text_after)
                    elements.append(md)

            return Group(*elements)
        else:
            # If no code blocks, but still contains markdown, use Rich's markdown renderer
            # Check for markdown elements (headers, lists, formatting)
            has_markdown = any(
                [
                    # Headers
                    re.search(r"^#{1,6}\s+\w+", raw_content, re.MULTILINE),
                    # Lists
                    re.search(r"^\s*[-*+]\s+\w+", raw_content, re.MULTILINE),
                    re.search(r"^\s*\d+\.\s+\w+", raw_content, re.MULTILINE),
                    # Bold/Italic
                    "**" in raw_content,
                    "*" in raw_content and "**" not in raw_content,
                    "__" in raw_content,
                    "_" in raw_content and "__" not in raw_content,
                    # Links
                    re.search(r"\[.+?\]\(.+?\)", raw_content),
                ]
            )

            if has_markdown:
                return Group(Markdown(raw_content))

    # For streaming mode or no markdown, return the raw content
    return raw_content


def parse_message_tool_call(message, tool_output=None):
    """
    Parse a message object to extract its content and tool calls.
    Displays tool calls in the format: tool_name({"command":"","args":"","ctf":{},"async_mode":false,"session_id":""})
    and shows the tool output in a separated panel.

    Args:
        message: A Message object or dict with content and tool_calls attributes
        tool_output: String containing the output from the tool execution

    Returns:
        tuple: (content, tool_panels) where content is the message text and
               tool_panels is a list of panels representing tool calls and outputs
    """
    content = ""
    tool_panels = []

    # Extract the content text (LLM's inference)
    if isinstance(message, str):
        content = message
    elif hasattr(message, "content") and message.content is not None:
        content = message.content
    elif isinstance(message, dict) and "content" in message:
        content = message["content"]

    # Extract tool calls
    tool_calls = None
    if hasattr(message, "tool_calls") and message.tool_calls:
        tool_calls = message.tool_calls
    elif isinstance(message, dict) and "tool_calls" in message and message["tool_calls"]:
        tool_calls = message["tool_calls"]

    # Process tool calls if they exist
    if tool_calls:
        for tool_call in tool_calls:
            # Extract tool name and arguments
            tool_name = None
            args_dict = {}
            call_id = None

            # Handle different formats of tool_call objects
            if hasattr(tool_call, "function"):
                if hasattr(tool_call.function, "name"):
                    tool_name = tool_call.function.name
                if hasattr(tool_call.function, "arguments"):
                    try:
                        args_dict = json.loads(tool_call.function.arguments)
                    except Exception:
                        args_dict = {"raw_arguments": tool_call.function.arguments}
            elif isinstance(tool_call, dict):
                if "function" in tool_call:
                    if "name" in tool_call["function"]:
                        tool_name = tool_call["function"]["name"]
                    if "arguments" in tool_call["function"]:
                        try:
                            args_dict = json.loads(tool_call["function"]["arguments"])
                        except Exception:
                            args_dict = {"raw_arguments": tool_call["function"]["arguments"]}

            # Create a panel for this tool call if name is not None
            # NOTE: Tool execution panel will be handled in cli_print_tool_output
            # Pass on tool info to generate panels for display in cli_print_agent_messages
            if tool_name and tool_output:
                # Skip creating tool output panel for execute_code
                # execute_code already shows its output through streaming panels
                if tool_name == "execute_code":
                    # Check if we're in streaming mode
                    streaming_enabled = os.getenv("KRYON_STREAM", "false").lower() == "true"
                    if streaming_enabled:
                        # Skip creating the panel - output already shown via streaming
                        continue

                # Create content for the panel - just showing the output, not the tool call
                panel_content = []

                # Add tool output to the panel
                output_text = Text()
                output_text.append("Output:", style="bold #C0C0C0")  # Silver/gray
                output_text.append(f"\n{tool_output}", style="#C0C0C0")  # Silver/gray

                panel_content.append(output_text)

                # Create a panel with just the output
                tool_panel = Panel(
                    Group(*panel_content),
                    border_style="cyan",
                    box=ROUNDED,
                    padding=(1, 2),
                    title="[bold]Tool Output[/bold]",  # Changed title to indicate this is just output
                    title_align="left",
                    expand=True,
                )

                tool_panels.append(tool_panel)

                # Store the call_id with tool name to help cli_print_tool_output avoid duplicates
                if not hasattr(parse_message_tool_call, "_processed_calls"):
                    parse_message_tool_call._processed_calls = set()

                call_key = call_id if call_id else f"{tool_name}:{args_dict}"
                parse_message_tool_call._processed_calls.add(call_key)

    return content, tool_panels


def is_tool_output_message(message):
    """Check if a message appears to be a tool output panel display message."""
    if isinstance(message, str):
        msg_lower = message.lower()
        return ("call id:" in msg_lower and "output:" in msg_lower) or msg_lower.startswith("tool output")
    return False


def print_message_history(messages, title="Message History"):
    """
    Pretty-print a sequence of messages with enhanced debug information.

    Args:
        messages (List[dict]): List of message dictionaries to display
        title (str, optional): Title to display above the message history
    """
    local_console = Console()

    # Create a table for displaying messages
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Role", style="cyan", width=10)
    table.add_column("Content", width=1000)
    table.add_column("Metadata", width=1000)

    # Process each message
    for i, msg in enumerate(messages):
        # Get role with color based on type
        role = msg.get("role", "unknown")
        role_style = {
            "user": "green",
            "assistant": "blue",
            "system": "yellow",
            "tool": "magenta",
        }.get(role, "white")

        # Get content preview
        content = msg.get("content")
        content_preview = ""
        if content is None:
            content_preview = "[dim]None[/dim]"
        elif isinstance(content, str):
            # Truncate and escape long content
            content_preview = (content[:37] + "...") if len(content) > 40 else content
            content_preview = content_preview.replace("\n", "\\n")
        elif isinstance(content, list):
            content_preview = f"[list with {len(content)} items]"
        else:
            content_preview = f"[{type(content).__name__}]"

        # Gather metadata
        metadata = []
        if msg.get("tool_calls"):
            tc_count = len(msg["tool_calls"])
            tc_info = []
            for tc in msg["tool_calls"]:
                tc_id = tc.get("id", "unknown")
                tc_name = tc.get("function", {}).get("name", "unknown") if "function" in tc else "unknown"
                tc_info.append(f"{tc_name}({tc_id})")
            metadata.append(f"tool_calls[{tc_count}]: {', '.join(tc_info)}")

        if msg.get("tool_call_id"):
            metadata.append(f"tool_call_id: {msg['tool_call_id']}")

        metadata_str = ", ".join(metadata)

        # Add row to table
        table.add_row(str(i), f"[{role_style}]{role}[/{role_style}]", content_preview, metadata_str)

    # Create the panel with the table
    panel = Panel(table, title=f"[bold]{title}[/bold]", expand=False)

    # Display the panel
    local_console.print(panel)

    return len(messages)  # Return message count for convenience


def _format_tool_args(args, tool_name=None):
    """Format tool arguments as a clean string."""
    # If the tool is execute_code, we don't want to show any args in the main header,
    # as they are detailed in subsequent panels (either code or args string).
    if tool_name == "execute_code":
        return ""

    # If args is already a string, it might be pre-formatted or a simple arg string
    if isinstance(args, str):
        # If it looks like a JSON dict string, try to parse and format nicely
        if args.strip().startswith("{") and args.strip().endswith("}"):
            try:
                parsed_dict = json.loads(args)
                # Recursively call with the parsed dict for consistent formatting
                return _format_tool_args(parsed_dict, tool_name=tool_name)
            except json.JSONDecodeError:
                # Not valid JSON, or not a dict; return as is
                return args
        else:
            # Simple string arg, return as is
            return args

    # Format arguments from a dictionary
    if isinstance(args, dict):
        # Only include non-empty values and exclude special flags
        arg_parts = []
        for key, value in args.items():
            # Skip empty values
            if value == "" or value == {} or value is None:
                continue
            # Skip special flags
            if key in ["async_mode", "streaming"] and not value:
                continue

            value_str = str(value)

            # Format the value
            if isinstance(value, str):
                # Truncate long string values
                if len(value_str) > 70 and key not in ["code", "args"]:
                    value_str = value_str[:67] + "..."
                arg_parts.append(f"{key}={value_str}")
            else:
                arg_parts.append(f"{key}={value_str}")
        return ", ".join(arg_parts)
    else:
        return str(args)


def _get_timing_info(execution_info=None):
    """Get timing information for display."""
    import time

    # Get session timing information
    try:
        from kryon.cli import START_TIME

        total_time = time.time() - START_TIME if START_TIME else None
    except ImportError:
        total_time = None

    # Extract execution timing info
    tool_time = None
    if execution_info:
        tool_time = execution_info.get("tool_time")

    # Format timing info for display
    timing_info = []
    if total_time:
        timing_info.append(f"Total: {format_time(total_time)}")
    if tool_time:
        timing_info.append(f"Tool: {format_time(tool_time)}")

    return timing_info, tool_time


def _create_token_display(
    interaction_input_tokens,
    interaction_output_tokens,
    interaction_reasoning_tokens,
    total_input_tokens,
    total_output_tokens,
    total_reasoning_tokens,
    model,
    interaction_cost=None,
    total_cost=None,
) -> Text:
    """Create token display text for agent messages."""
    # Standardize model name
    model_name = get_model_name(model)

    # Use the provided costs directly if available, otherwise use the last tracked values
    # DO NOT process costs here - this function is called multiple times for display
    if interaction_cost is not None:
        current_cost = float(interaction_cost)
    else:
        # Use the last recorded interaction cost
        current_cost = COST_TRACKER.last_interaction_cost

    if total_cost is not None:
        total_cost_value = float(total_cost)
    else:
        # Use the last recorded total cost
        total_cost_value = COST_TRACKER.last_total_cost

    # F77.D / Fase 5: compact footer. One line, dim cyan, semantic context indicator.
    # Old: "Current: I:N O:N R:N (cost) | Total:... | Session: $X | Context: X% OK"
    # New: "I:N O:N · ctx X% OK"  (R: only when > 0; cost only when relevant)
    tokens_text = Text(justify="left")
    show_cost = not _hide_cost()

    tokens_text.append(
        f"I:{interaction_input_tokens} O:{interaction_output_tokens}",
        style="dim cyan",
    )
    if interaction_reasoning_tokens > 0:
        tokens_text.append(f" R:{interaction_reasoning_tokens}", style="dim cyan")
    if show_cost and current_cost > 0:
        tokens_text.append(f" (${current_cost:.4f})", style="dim")

    context_pct = interaction_input_tokens / get_model_input_tokens(model_name) * 100
    if context_pct < 50:
        indicator = "OK"
        color_local = "green"
    elif context_pct < 80:
        indicator = "!!"
        color_local = "yellow"
    else:
        indicator = "XX"
        color_local = "red"

    tokens_text.append(" · ", style="dim")
    tokens_text.append(f"ctx {context_pct:.0f}%", style="dim cyan")
    tokens_text.append(" ", style="dim")
    tokens_text.append(indicator, style=color_local)

    return tokens_text


def _create_token_info_display(token_info=None):
    """Create token information display text."""
    if not token_info:
        return None

    model = token_info.get("model", "")
    interaction_input_tokens = token_info.get("interaction_input_tokens", 0)
    interaction_output_tokens = token_info.get("interaction_output_tokens", 0)
    interaction_reasoning_tokens = token_info.get("interaction_reasoning_tokens", 0)
    total_input_tokens = token_info.get("total_input_tokens", 0)
    total_output_tokens = token_info.get("total_output_tokens", 0)
    total_reasoning_tokens = token_info.get("total_reasoning_tokens", 0)

    # Only continue if we have actual token information
    if not (interaction_input_tokens > 0 or total_input_tokens > 0):
        return None

    # Create token display
    return _create_token_display(
        interaction_input_tokens,
        interaction_output_tokens,
        interaction_reasoning_tokens,
        total_input_tokens,
        total_output_tokens,
        total_reasoning_tokens,
        model,
        token_info.get("interaction_cost"),
        token_info.get("total_cost"),
    )


def cli_print_agent_messages(
    agent_name,
    message,
    counter,
    model,
    debug,  # pylint: disable=too-many-arguments,too-many-locals,unused-argument
    interaction_input_tokens=None,
    interaction_output_tokens=None,
    interaction_reasoning_tokens=None,
    total_input_tokens=None,
    total_output_tokens=None,
    total_reasoning_tokens=None,
    interaction_cost=None,
    total_cost=None,
    tool_output=None,  # New parameter for tool output
    suppress_empty=False,  # New parameter to suppress empty panels
    token_info=None,  # Token info dict with agent_name, agent_id, etc.
):
    """Print agent messages/thoughts with enhanced visual formatting."""
    # Import here to avoid circular imports
    from kryon.util.streaming import start_tool_streaming

    # Debug prints to trace the function calls
    if debug:
        if isinstance(message, str):
            print(f"DEBUG cli_print_agent_messages: Received string message: {message[:50]}...")
        if tool_output:
            print(f"DEBUG cli_print_agent_messages: Received tool_output: {tool_output[:50]}...")

    # Don't override the model - use the agent's actual model

    timestamp = datetime.now().strftime("%H:%M:%S")

    # Create header
    text = Text()

    # Check if the message has tool calls
    has_tool_calls = False
    if hasattr(message, "tool_calls") and message.tool_calls:
        has_tool_calls = True
        # Check if this is an execute_code tool call
        for tool_call in message.tool_calls:
            if hasattr(tool_call, "function") and hasattr(tool_call.function, "name"):
                if tool_call.function.name == "execute_code":
                    break
    elif isinstance(message, dict) and "tool_calls" in message and message["tool_calls"]:
        has_tool_calls = True
        # Check if this is an execute_code tool call
        for tool_call in message["tool_calls"]:
            if isinstance(tool_call, dict) and "function" in tool_call:
                if tool_call["function"].get("name") == "execute_code":
                    break

    # Parse the message based on whether it has tool calls
    if has_tool_calls:
        parsed_message, tool_panels = parse_message_tool_call(message, tool_output)
    else:
        parsed_message = parse_message_content(message)
        tool_panels = []

    # Check if this is the main agent displaying a parallel agent's execute_code output
    # This happens when parallel results are added to message history
    if (
        isinstance(parsed_message, str)
        and hasattr(start_tool_streaming, "_parallel_execute_code_agents")
        and any(
            parallel_agent in parsed_message
            for parallel_agent in start_tool_streaming._parallel_execute_code_agents
            if parallel_agent
        )
        and token_info
        and token_info.get("agent_name") not in start_tool_streaming._parallel_execute_code_agents
    ):
        # This is the main agent displaying output from a parallel agent that used execute_code
        # Check if it contains execute_code output patterns (code blocks)
        if "```" in parsed_message and any(
            pattern in parsed_message.lower() for pattern in ["package main", "def ", "function", "import ", "class "]
        ):
            # Replace the execute_code output with a brief message
            lines = parsed_message.split("\n")
            summary_lines = []
            for line in lines:
                if "```" in line:
                    break
                summary_lines.append(line)

            if summary_lines:
                parsed_message = (
                    "\n".join(summary_lines).strip() + "\n\n[Execute code output already shown in panels above]"
                )
            else:
                parsed_message = "[Execute code output already shown in panels above]"

    # Special handling for async session messages
    if tool_output and ("Started async session" in tool_output or "session" in tool_output.lower()):
        # For async session creation, show the session message as the main content
        if not parsed_message or parsed_message == "null" or parsed_message == "":
            parsed_message = tool_output
        else:
            # If there's already content, append the session message
            parsed_message = f"{parsed_message}\n\n{tool_output}"

        # Clear tool_panels to avoid duplication since we're showing the session message as main content
        tool_panels = []

    # Skip empty panels - THIS IS THE KEY CHANGE
    # If suppress_empty is True and there's no parsed message and no tool panels,
    # don't create an empty panel to avoid cluttering during streaming
    if suppress_empty and not parsed_message and not tool_panels:
        return

    # Check if parsed_message is empty or "null"
    is_empty_message = (
        parsed_message == "null"
        or parsed_message == ""
        or (isinstance(parsed_message, str) and not parsed_message.strip())
    )

    # Also skip if the only message is "null" or empty
    if is_empty_message:
        if suppress_empty and not tool_panels:
            return

    # Check if we have Group content from markdown parsing
    is_rich_content = False

    if isinstance(parsed_message, Group):
        is_rich_content = True

    # Special handling for Reasoner Agent
    if agent_name == "Reasoner Agent":
        text.append(f"[{counter}] ", style="bold red")
        text.append(f"Agent: {agent_name} ", style="bold yellow")
        if parsed_message and not is_rich_content:
            text.append(f">> {parsed_message} ", style="green")
        text.append(f"[{timestamp}", style="dim")
        if model:
            text.append(f" ({os.getenv('KRYON_SUPPORT_MODEL')})", style="bold blue")
        text.append("]", style="dim")
    elif is_empty_message:
        # When parsed_message is empty, only include timestamp and model info
        text.append(f"Agent: {agent_name} ", style="bold green")
        text.append(f"[{timestamp}", style="dim")
        if model:
            text.append(f" ({model})", style="bold magenta")
        text.append("]", style="dim")
    else:
        text.append(f"[{counter}] ", style="bold cyan")
        text.append(f"Agent: {agent_name} ", style="bold green")
        if parsed_message and not is_rich_content:
            text.append(f">> {parsed_message} ", style="yellow")
        text.append(f"[{timestamp}", style="dim")
        if model:
            text.append(f" ({model})", style="bold magenta")
        text.append("]", style="dim")

    # Add token information with enhanced formatting
    tokens_text = None
    if (
        interaction_input_tokens is not None  # pylint: disable=R0916
        and interaction_output_tokens is not None
        and interaction_reasoning_tokens is not None
        and total_input_tokens is not None
        and total_output_tokens is not None
        and total_reasoning_tokens is not None
    ):
        tokens_text = _create_token_display(
            interaction_input_tokens,
            interaction_output_tokens,
            interaction_reasoning_tokens,
            total_input_tokens,
            total_output_tokens,
            total_reasoning_tokens,
            model,
            interaction_cost,
            total_cost,
        )
        # Only append token information if there is a parsed message
        if parsed_message and not is_rich_content:
            text.append(tokens_text)

    # F77.D / Fase 9: agent narrative renders inline (no Panel envelope).
    # Reasoner Agent kept its red panel because it's a separate sub-flow
    # whose output the operator wants visually segregated.
    if agent_name == "Reasoner Agent":
        if is_rich_content:
            panel_content = [text, Text("\n"), parsed_message]
            if tokens_text:
                panel_content.extend([Text("\n"), tokens_text])
            panel = Panel(
                Group(*panel_content),
                border_style="red",
                box=ROUNDED,
                padding=(1, 1),
                title="",
                title_align="left",
            )
        else:
            panel = Panel(
                text,
                border_style="red",
                box=ROUNDED,
                padding=(0, 1),
                title="",
                title_align="left",
            )
        console.print(panel)
    else:
        if is_rich_content:
            panel_content = [text, Text("\n"), parsed_message]
            if tokens_text:
                panel_content.extend([Text("\n"), tokens_text])
            console.print(Group(*panel_content))
        else:
            console.print(text)

    # If there are tool panels, print them after the main message panel
    # But only in non-streaming mode to avoid duplicates
    if tool_panels:
        for tool_panel in tool_panels:
            console.print(tool_panel)
