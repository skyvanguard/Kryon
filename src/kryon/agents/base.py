"""
Agent creation helpers — eliminates boilerplate across agent modules.

Provides a shared model factory and agent creation shortcut so each
agent module only needs to specify its unique parts (name, instructions,
tools, guardrails, handoffs).
"""

import os

from openai import AsyncOpenAI

from kryon.sdk.agents import Agent, OpenAIChatCompletionsModel


def chat_model_cls() -> type[OpenAIChatCompletionsModel]:
    """Pick the chat-model class.

    Default is now the native AsyncOpenAI model (no litellm): Kryon's runtime
    is 100% OpenAI-compatible (local Qwen MoE + DeepSeek), so the native client
    with ``base_url`` handles it directly — without litellm's per-provider
    branching, drop_params toggling, ``openai/<model>`` prefix hack, or its
    fragile internals (validated live against the local MoE).

    Escape hatch: ``KRYON_USE_LITELLM=true`` restores the litellm-backed model
    for any provider that genuinely needs litellm's translation layer.
    ``KRYON_USE_NATIVE_OPENAI`` is still honored (forces native) for parity
    with the spike rollout.
    """
    if os.getenv("KRYON_USE_LITELLM", "").strip().lower() in ("1", "true", "yes"):
        return OpenAIChatCompletionsModel
    # Default + explicit opt-in both resolve to native.
    from kryon.sdk.agents.models.openai_native import OpenAINativeModel

    return OpenAINativeModel


def get_default_model() -> OpenAIChatCompletionsModel:
    """Create a shared chat model from environment config.

    Reads OPENAI_BASE_URL so non-default providers (Groq, OpenRouter,
    DeepSeek) work without an extra step. Without an explicit base_url
    the AsyncOpenAI client targets api.openai.com and 401s on any other
    provider's key.
    """
    return chat_model_cls()(
        model=os.getenv("KRYON_MODEL", "Kryon-MOE-35B"),
        openai_client=AsyncOpenAI(
            api_key=os.getenv("OPENAI_API_KEY", "not-set"),
            base_url=os.getenv("OPENAI_BASE_URL"),
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
