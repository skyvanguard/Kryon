"""
Agent creation helpers — eliminates boilerplate across agent modules.

Provides a shared model factory and agent creation shortcut so each
agent module only needs to specify its unique parts (name, instructions,
tools, guardrails, handoffs).
"""

import logging

from openai import AsyncOpenAI

from kryon.config import settings
from kryon.sdk.agents import Agent, OpenAIChatCompletionsModel

logger = logging.getLogger(__name__)

# Substrings that mark a cloud (paid, off-perimeter) model.
_CLOUD_MARKERS = ("deepseek", "gpt-", "o1", "o3", "o4-", "claude", "gemini", "openai/")
# API-key values that mean "not actually configured".
_PLACEHOLDER_KEYS = {"", "not-set", "llama", "none", "placeholder", "sk-xxx"}


def is_cloud_model(model: str | None) -> bool:
    """True for a cloud provider model (paid, leaves the engagement perimeter)."""
    s = (model or "").lower()
    return any(m in s for m in _CLOUD_MARKERS)


def validate_model_config() -> tuple[bool, list[str]]:
    """Fail-fast check for the selected model. Returns (ok, issues). A cloud model
    needs a real API key (and DeepSeek its own base_url + KRYON_LOCAL_LLM=false) —
    catching it here avoids a cryptic mid-run 401/timeout that wastes a paid run."""
    s = settings(refresh=True)
    issues: list[str] = []
    if is_cloud_model(s.model):
        if (s.openai_api_key or "").strip().lower() in _PLACEHOLDER_KEYS:
            issues.append(
                f"model '{s.model}' is a cloud model but OPENAI_API_KEY is unset/placeholder "
                f"('{s.openai_api_key}') — set a real key."
            )
        if "deepseek" in (s.model or "").lower() and "deepseek" not in (s.openai_base_url or "").lower():
            issues.append(
                "DeepSeek selected but OPENAI_BASE_URL does not point at DeepSeek "
                "(set OPENAI_BASE_URL=https://api.deepseek.com)."
            )
        if s.local_llm:
            issues.append(
                f"KRYON_LOCAL_LLM=true with cloud model '{s.model}' — set KRYON_LOCAL_LLM=false "
                "(the local-LLM parsers/usage patch assume a local server)."
            )
    return (not issues), issues


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
    ok, issues = validate_model_config()
    if not ok:
        for i in issues:
            logger.warning("model config: %s", i)
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
