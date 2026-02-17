#!/usr/bin/env python3
"""
Example: Using Claude Code CLI as KRYON's LLM backend.

This example demonstrates how to use your Claude Pro Max subscription
(via Claude Code CLI) instead of separate API keys.

Requirements:
- Claude Code CLI installed and authenticated (`claude --version`)
- KRYON installed (`pip install -e .`)

Usage:
    python examples/claude_code_backend_example.py
"""

import asyncio
import sys

# Fix Windows encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# Disable tracing to avoid API key errors
from kryon.sdk.agents.tracing import set_tracing_disabled
set_tracing_disabled(True)

from kryon.sdk.agents import Agent, RunConfig, Runner, function_tool
from kryon.sdk.agents.models.claude_code_provider import ClaudeCodeProvider


# Define a simple tool for the agent
@function_tool
def get_current_time() -> str:
    """Get the current date and time."""
    from datetime import datetime

    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@function_tool
def calculate(expression: str) -> str:
    """Evaluate a mathematical expression safely."""
    # Only allow safe characters
    allowed = set("0123456789+-*/.() ")
    if not all(c in allowed for c in expression):
        return "Error: Invalid characters in expression"
    try:
        result = eval(expression)  # Safe because we filtered input
        return str(result)
    except Exception as e:
        return f"Error: {e}"


# Create a simple agent
test_agent = Agent(
    name="Claude Code Test Agent",
    description="A test agent powered by Claude Code CLI",
    instructions="""You are a helpful assistant that can:
1. Tell the current time
2. Perform calculations

Be concise and helpful in your responses.""",
    tools=[get_current_time, calculate],
)


async def main():
    print("=" * 60)
    print("KRYON + Claude Code CLI Integration Test")
    print("=" * 60)
    print()

    # Create the Claude Code provider
    # You can change the model to "opus" or "haiku" if needed
    provider = ClaudeCodeProvider(
        default_model="sonnet",  # Use Claude Sonnet
        timeout=120,  # 2 minute timeout
    )

    # Create run config with Claude Code as the backend
    config = RunConfig(model_provider=provider)

    # Test prompt
    prompt = "What time is it? Also, what is 42 * 17?"

    print(f"Prompt: {prompt}")
    print("-" * 60)

    try:
        # Run the agent
        result = await Runner.run(
            test_agent,
            prompt,
            run_config=config,
        )

        print("Response:")
        print(result.final_output)

    except Exception as e:
        print(f"Error: {e}")
        print()
        print("Troubleshooting:")
        print("1. Make sure Claude Code CLI is installed: claude --version")
        print("2. Make sure you're authenticated: claude")
        print("3. Check if you have a Pro Max subscription")


if __name__ == "__main__":
    asyncio.run(main())
