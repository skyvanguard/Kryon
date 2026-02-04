"""
KRYON utility module package.

This module provides utilities for:
- Timing (active/idle time tracking)
- Cost tracking (API costs)
- Templates (prompt loading)
- Visualization (agent graph)
- Message utilities (parsing, fixing messages)
- Streaming (Rich UI for tool/agent output)
- CTF (Capture The Flag utilities)
- Thinking (Claude/AI reasoning display)

All public functions are re-exported here for backward compatibility.
"""

# Re-export wasabi color for backward compatibility
from wasabi import color

# Cost tracking utilities
from skynet.util.cost_tracker import (
    COST_TRACKER,
    CostTracker,
    calculate_model_cost,
    format_time,
    get_model_input_tokens,
    get_model_name,
    get_model_pricing,
)

# CTF utilities
from skynet.util.ctf import (
    check_flag,
    setup_ctf,
)

# Message utilities
from skynet.util.message_utils import (
    _create_token_display,
    _create_token_info_display,
    _format_tool_args,
    _get_timing_info,
    cli_print_agent_messages,
    cli_print_tool_call,
    fix_litellm_transcription_annotations,
    fix_message_list,
    get_language_from_code_block,
    is_tool_output_message,
    parse_message_content,
    parse_message_tool_call,
    print_message_history,
)

# Streaming utilities
from skynet.util.streaming import (
    # Global variables that may be needed
    _LIVE_STREAMING_PANELS,
    _PANEL_UPDATE_LOCK,
    _PARALLEL_EXECUTION_STATE,
    _create_tool_panel_content,
    _print_simple_tool_output,
    cleanup_agent_streaming_resources,
    cleanup_all_streaming_resources,
    cli_print_tool_output,
    create_agent_streaming_context,
    finish_agent_streaming,
    finish_tool_streaming,
    signal_handler,
    start_tool_streaming,
    update_agent_streaming_content,
    update_tool_streaming,
)

# Template utilities
from skynet.util.templates import (
    append_instructions,
    create_system_prompt_renderer,
    get_ollama_api_base,
    load_prompt_template,
)

# Thinking display utilities
from skynet.util.thinking import (
    _CLAUDE_THINKING_PANELS,
    cleanup_thinking_panels,
    create_claude_thinking_context,
    detect_claude_thinking_in_stream,
    finish_claude_thinking_display,
    get_thinking_panels,
    print_claude_reasoning_simple,
    start_claude_thinking_if_applicable,
    update_claude_thinking_content,
)
from skynet.util.timing import (
    get_active_time,
    get_active_time_seconds,
    get_idle_time,
    get_idle_time_seconds,
    start_active_timer,
    start_idle_timer,
    stop_active_timer,
    stop_idle_timer,
)

# Visualization utilities
from skynet.util.visualization import (
    visualize_agent_graph,
)

__all__ = [
    # External re-exports
    "color",
    # Timing
    "start_active_timer",
    "stop_active_timer",
    "start_idle_timer",
    "stop_idle_timer",
    "get_active_time",
    "get_idle_time",
    "get_active_time_seconds",
    "get_idle_time_seconds",
    # Cost tracking
    "CostTracker",
    "COST_TRACKER",
    "get_model_name",
    "get_model_input_tokens",
    "get_model_pricing",
    "calculate_model_cost",
    "format_time",
    # Templates
    "get_ollama_api_base",
    "load_prompt_template",
    "create_system_prompt_renderer",
    "append_instructions",
    # Visualization
    "visualize_agent_graph",
    # Message utilities
    "fix_litellm_transcription_annotations",
    "fix_message_list",
    "get_language_from_code_block",
    "cli_print_tool_call",
    "parse_message_content",
    "parse_message_tool_call",
    "is_tool_output_message",
    "print_message_history",
    "cli_print_agent_messages",
    "_format_tool_args",
    "_get_timing_info",
    "_create_token_display",
    "_create_token_info_display",
    # Streaming
    "cleanup_all_streaming_resources",
    "cleanup_agent_streaming_resources",
    "signal_handler",
    "create_agent_streaming_context",
    "update_agent_streaming_content",
    "finish_agent_streaming",
    "cli_print_tool_output",
    "_print_simple_tool_output",
    "_create_tool_panel_content",
    "start_tool_streaming",
    "update_tool_streaming",
    "finish_tool_streaming",
    "_LIVE_STREAMING_PANELS",
    "_PANEL_UPDATE_LOCK",
    "_PARALLEL_EXECUTION_STATE",
    # CTF
    "check_flag",
    "setup_ctf",
    # Thinking
    "create_claude_thinking_context",
    "update_claude_thinking_content",
    "finish_claude_thinking_display",
    "detect_claude_thinking_in_stream",
    "print_claude_reasoning_simple",
    "start_claude_thinking_if_applicable",
    "get_thinking_panels",
    "cleanup_thinking_panels",
    "_CLAUDE_THINKING_PANELS",
]
