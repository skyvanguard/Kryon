"""
Agent creation helpers — eliminates boilerplate across agent modules.

Provides a shared model factory and agent creation shortcut so each
agent module only needs to specify its unique parts (name, instructions,
tools, guardrails, handoffs).
"""

from openai import AsyncOpenAI

from kryon.config import settings
from kryon.sdk.agents import Agent, OpenAIChatCompletionsModel


def chat_model_cls() -> type[OpenAIChatCompletionsModel]:
    """Pick the chat-model class.

    Default is the native AsyncOpenAI model (no litellm): Kryon's runtime is
    100% OpenAI-compatible (local Qwen MoE + DeepSeek), so the native client
    with ``base_url`` handles it directly — without litellm's per-provider
    branching, drop_params toggling, ``openai/<model>`` prefix hack, or its
    fragile internals (validated live against the local MoE).

    Escape hatch: ``KRYON_USE_LITELLM=true`` restores the litellm-backed model.
    """
    if settings(refresh=True).use_litellm:
        return OpenAIChatCompletionsModel
    from kryon.sdk.agents.models.openai_native import OpenAINativeModel

    return OpenAINativeModel


def get_default_model() -> OpenAIChatCompletionsModel:
    """Create a shared chat model from the central config (KryonSettings).

    Reads OPENAI_BASE_URL so non-default OpenAI-compatible providers (DeepSeek,
    local llama-server) work without an extra step. Without an explicit
    base_url the AsyncOpenAI client targets api.openai.com.
    """
    s = settings(refresh=True)
    return chat_model_cls()(
        model=s.model,
        openai_client=AsyncOpenAI(api_key=s.openai_api_key, base_url=s.openai_base_url),
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
