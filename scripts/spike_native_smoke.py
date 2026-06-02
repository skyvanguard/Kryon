"""Live smoke for the native-OpenAI spike against the local Qwen MoE.

Runs a real tool-calling round-trip through OpenAINativeModel (no litellm) to
confirm the MoE's --jinja tool-calling works via the native openai client.
Point it at the live llama-server. Run:

    OPENAI_BASE_URL=http://localhost:8081/v1 OPENAI_API_KEY=sk-noauth \
    KRYON_MODEL=Kryon-MOE-35B KRYON_LOCAL_LLM=true KRYON_USE_NATIVE_OPENAI=true \
    uv run python scripts/spike_native_smoke.py
"""

from __future__ import annotations

import asyncio
import os

from kryon.sdk.agents import Agent, Runner, function_tool
from kryon.agents.base import chat_model_cls, get_default_model


@function_tool(strict_mode=False)
def add_numbers(a: int, b: int) -> str:
    """Add two integers and return the sum."""
    return str(a + b)


async def main() -> None:
    model = get_default_model()
    print(f"model class : {type(model).__name__}")
    print(f"native flag : {os.getenv('KRYON_USE_NATIVE_OPENAI')!r}")
    print(f"endpoint    : {os.getenv('OPENAI_BASE_URL')!r}")
    print(f"model name  : {model.model}\n")

    agent = Agent(
        name="smoke",
        instructions="You are a calculator. Use the add_numbers tool to add.",
        tools=[add_numbers],
        model=model,
    )
    result = await Runner.run(agent, input="What is 17 + 25? Use the tool.", max_turns=4)

    tool_calls = [
        it for it in (result.new_items or [])
        if getattr(it, "type", "") == "tool_call_item"
    ]
    print(f"tool calls  : {len(tool_calls)}")
    for tc in tool_calls:
        raw = getattr(tc, "raw_item", None)
        print(f"  -> {getattr(raw, 'name', '?')} args={getattr(raw, 'arguments', '?')}")
    print(f"\nfinal_output: {result.final_output!r}")
    ok = "42" in str(result.final_output) or any(tool_calls)
    print(f"\nSMOKE {'PASS' if ok else 'INCONCLUSIVE'} "
          f"(class={type(model).__name__})")


if __name__ == "__main__":
    asyncio.run(main())
