"""
Agent creation helpers — eliminates boilerplate across agent modules.

Provides a shared model factory and agent creation shortcut so each
agent module only needs to specify its unique parts (name, instructions,
tools, guardrails, handoffs).
"""

import os

from openai import AsyncOpenAI

from kryon.sdk.agents import Agent, OpenAIChatCompletionsModel


def get_default_model() -> OpenAIChatCompletionsModel:
    """Create a shared OpenAIChatCompletionsModel from environment config."""
    return OpenAIChatCompletionsModel(
        model=os.getenv("KRYON_MODEL", "gpt-4o"),
        openai_client=AsyncOpenAI(
            api_key=os.getenv("OPENAI_API_KEY", "not-set"),
        ),
    )


def create_agent(name: str, instructions, tools, *, description: str = "", **kwargs) -> Agent:
    """Factory with sensible defaults — pass model= to override."""
    model = kwargs.pop("model", None) or get_default_model()
    return Agent(
        name=name,
        instructions=instructions,
        tools=tools,
        description=description,
        model=model,
        **kwargs,
    )
