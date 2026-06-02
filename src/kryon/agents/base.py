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

    Auto-exception: DeepSeek "thinking" models (deepseek-reasoner / deepseek-v4-*,
    NOT deepseek-chat) REQUIRE the assistant's ``reasoning_content`` to be echoed
    back on every subsequent turn, or the API 400s mid-run
    ('The reasoning_content in the thinking mode must be passed back to the API.').
    The native path doesn't round-trip it; litellm's DeepSeek provider does — so
    those models are auto-routed to the litellm backend. Everything else (local
    MoE, deepseek-chat, plain OpenAI-compatible) stays on the litellm-free native
    default. Selecting the litellm class does NOT import litellm (the import stays
    lazy inside its ``_fetch_response``), so the P1 import invariant holds.
    """
    s = settings(refresh=True)
    if s.use_litellm or _needs_litellm_for_reasoning(s.model):
        return OpenAIChatCompletionsModel
    from kryon.sdk.agents.models.openai_native import OpenAINativeModel

    return OpenAINativeModel


def _needs_litellm_for_reasoning(model: str | None) -> bool:
    """True for DeepSeek thinking models that need litellm's reasoning_content
    round-trip. Mirrors ``openai_chatcompletions._preserves_reasoning_in_history``:
    ``deepseek`` in the name but NOT ``deepseek-chat`` (the non-reasoning V3 chat
    model, which works fine on the native path)."""
    s = (model or "").lower()
    return "deepseek" in s and "deepseek-chat" not in s


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
