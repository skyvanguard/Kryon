"""
Cost tracking utilities for KRYON.

Tracks USD spend on hosted LLM APIs (DeepSeek primarily). Local models
(Ollama-served qwen3/llama3/etc) are free and report $0.

Pricing source: official DeepSeek API docs (May 2026). Update PRICING_USD
when DeepSeek announces new tiers or post-promo pricing kicks in.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# Per-million-token pricing in USD. (input_miss, input_hit, output)
# - input_miss: regular input tokens (cache miss).
# - input_hit:  prompt-cache hits (~10% of miss for DeepSeek).
# - output:     completion tokens including reasoning.
#
# Reference: https://api-docs.deepseek.com/quick_start/pricing (May 2026).
PRICING_USD: dict[str, tuple[float, float, float]] = {
    # DeepSeek V4 Flash and its legacy aliases — all route to the same
    # underlying weights at the same price. deepseek-reasoner is the
    # thinking-on alias; deepseek-chat is thinking-off; both bill identically.
    "deepseek-v4-flash": (0.14, 0.0028, 0.28),
    "deepseek-chat": (0.14, 0.0028, 0.28),
    "deepseek-reasoner": (0.14, 0.0028, 0.28),
    # V4 Pro is on a 75% launch promo through 2026-05-31. Update when the
    # promo expires: post-promo prices are (1.74, 0.0145, 3.48).
    "deepseek-v4-pro": (0.435, 0.003625, 0.87),
    # Groq paid tier — free tier returns $0 because it's metered separately.
    # Pricing reference: https://groq.com/pricing (May 2026).
    # Cache hits not separately priced — Groq prefix-caches transparently.
    "llama-3.3-70b-versatile": (0.59, 0.59, 0.79),
    "llama-3.1-8b-instant": (0.05, 0.05, 0.08),
    "qwen/qwen3-32b": (0.29, 0.29, 0.59),
    "qwen3-32b": (0.29, 0.29, 0.59),
    "openai/gpt-oss-20b": (0.10, 0.10, 0.50),
    "openai/gpt-oss-120b": (0.15, 0.15, 0.75),
    "meta-llama/llama-4-scout-17b-16e-instruct": (0.11, 0.11, 0.34),
    # OpenRouter free tier — explicit zero so they bypass the substring
    # fallback and never charge. The `:free` suffix is part of the model id.
    "openai/gpt-oss-120b:free": (0.0, 0.0, 0.0),
    "openai/gpt-oss-20b:free": (0.0, 0.0, 0.0),
    "qwen/qwen3-next-80b-a3b-instruct:free": (0.0, 0.0, 0.0),
    "qwen/qwen3-coder:free": (0.0, 0.0, 0.0),
    "nvidia/nemotron-3-super-120b-a12b:free": (0.0, 0.0, 0.0),
    "minimax/minimax-m2.5:free": (0.0, 0.0, 0.0),
    "z-ai/glm-4.5-air:free": (0.0, 0.0, 0.0),
    "meta-llama/llama-3.3-70b-instruct:free": (0.0, 0.0, 0.0),
    # Local Ollama models — explicit zero so they never hit the catch-all.
    "qwen3": (0.0, 0.0, 0.0),
    "qwen2.5": (0.0, 0.0, 0.0),
    "llama3": (0.0, 0.0, 0.0),
    "kryon-14b": (0.0, 0.0, 0.0),
    "kryon-r1-14b": (0.0, 0.0, 0.0),
}

CONTEXT_WINDOW: dict[str, int] = {
    "deepseek-v4-flash": 1_000_000,
    "deepseek-chat": 1_000_000,
    "deepseek-reasoner": 1_000_000,
    "deepseek-v4-pro": 1_000_000,
    "deepseek": 128_000,  # legacy fallback for unrecognised deepseek-*
    "qwen3": 32_000,
    "qwen2.5": 32_000,
    "llama3.1": 32_000,
    "gpt": 128_000,
    "o1": 200_000,
    "claude": 200_000,
}


def get_model_name(model) -> str:
    """Extract a string model name from various model inputs."""
    if isinstance(model, str):
        return model
    return os.environ.get("KRYON_MODEL", "qwen3:8b")


def get_model_input_tokens(model) -> int:
    """Get max context window tokens for a model."""
    name = get_model_name(model).lower()
    # Exact-match first (more specific wins)
    if name in CONTEXT_WINDOW:
        return CONTEXT_WINDOW[name]
    for prefix, tokens in CONTEXT_WINDOW.items():
        if prefix in name:
            return tokens
    return 32_000


def format_time(seconds) -> str:
    """Format time in a human-readable way."""
    if seconds is None:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        seconds_remainder = seconds % 60
        return f"{minutes}m {seconds_remainder:.1f}s"
    else:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h {minutes}m"


def get_model_pricing(model_name) -> tuple[float, float]:
    """Return (input_miss_per_M, output_per_M) in USD. Backwards-compat
    2-tuple — callers that need cache-hit pricing should use
    `_get_full_pricing` directly."""
    miss, _hit, out = _get_full_pricing(model_name)
    return (miss, out)


def _get_full_pricing(model_name) -> tuple[float, float, float]:
    """Return (input_miss, input_hit, output) per million tokens in USD."""
    name = get_model_name(model_name).lower()
    if name in PRICING_USD:
        return PRICING_USD[name]
    # Substring fallback (catches "deepseek/deepseek-chat" or "openrouter/...")
    for key, prices in PRICING_USD.items():
        if key in name:
            return prices
    return (0.0, 0.0, 0.0)


def calculate_model_cost(model, input_tokens: int, output_tokens: int) -> float:
    """Calculate cost assuming all input is cache-miss. Use
    `calculate_cost_with_cache` for accurate billing on long sessions."""
    miss_per_m, out_per_m = get_model_pricing(model)
    return ((input_tokens / 1_000_000) * miss_per_m) + ((output_tokens / 1_000_000) * out_per_m)


def calculate_cost_with_cache(
    model,
    input_miss_tokens: int,
    input_hit_tokens: int,
    output_tokens: int,
) -> float:
    """Accurate cost when the API response separates cache hits from misses.
    DeepSeek returns these in `response.usage.prompt_cache_hit_tokens` and
    `response.usage.prompt_cache_miss_tokens`."""
    miss_per_m, hit_per_m, out_per_m = _get_full_pricing(model)
    return (
        (input_miss_tokens / 1_000_000) * miss_per_m
        + (input_hit_tokens / 1_000_000) * hit_per_m
        + (output_tokens / 1_000_000) * out_per_m
    )


@dataclass
class CostTracker:
    """Tracks running cost across a Kryon session.

    All cost methods are no-ops for models priced at $0 (local Ollama),
    so the tracker stays cheap even when never exercised.
    """

    session_total_cost: float = 0.0
    current_agent_total_cost: float = 0.0
    current_agent_input_tokens: int = 0
    current_agent_output_tokens: int = 0
    current_agent_reasoning_tokens: int = 0
    interaction_input_tokens: int = 0
    interaction_output_tokens: int = 0
    interaction_reasoning_tokens: int = 0
    interaction_cost: float = 0.0
    model_pricing_cache: dict[str, tuple] = field(default_factory=dict)
    calculated_costs_cache: dict[str, float] = field(default_factory=dict)
    last_interaction_cost: float = 0.0
    last_total_cost: float = 0.0
    # Optional hard limit (USD). Set via KRYON_PRICE_LIMIT env. "inf" = no limit.
    price_limit: float = field(default_factory=lambda: _parse_price_limit())

    def check_price_limit(self, new_cost: float) -> None:
        """Raise RuntimeError if adding `new_cost` would exceed price_limit.
        Used to abort long-running sessions before they overrun budget."""
        if self.price_limit < float("inf") and (self.session_total_cost + new_cost) > self.price_limit:
            raise RuntimeError(
                f"KRYON_PRICE_LIMIT exceeded: "
                f"running ${self.session_total_cost:.4f} + ${new_cost:.4f} > ${self.price_limit:.2f}"
            )

    def update_session_cost(self, new_cost: float) -> None:
        self.session_total_cost += new_cost
        self.last_total_cost = self.session_total_cost

    def add_interaction_cost(self, new_cost: float) -> None:
        self.interaction_cost = new_cost
        self.last_interaction_cost = new_cost
        self.update_session_cost(new_cost)

    def reset_cost_for_local_model(self, model_name: str) -> bool:
        """Returns True for models priced at zero (local Ollama). Callers
        skip tracking when this is True."""
        miss, _hit, out = _get_full_pricing(model_name)
        return miss == 0.0 and out == 0.0

    def reset_agent_costs(self) -> None:
        self.current_agent_input_tokens = 0
        self.current_agent_output_tokens = 0
        self.current_agent_reasoning_tokens = 0
        self.interaction_input_tokens = 0
        self.interaction_output_tokens = 0
        self.interaction_reasoning_tokens = 0

    def log_final_cost(self) -> None:
        if self.session_total_cost > 0:
            print(
                f"💰 Session cost: ${self.session_total_cost:.4f} "
                f"(input={self.current_agent_input_tokens:,}, "
                f"output={self.current_agent_output_tokens:,}, "
                f"reasoning={self.current_agent_reasoning_tokens:,})"
            )

    def get_model_pricing(self, model_name: str) -> tuple[float, float]:
        return get_model_pricing(model_name)

    def calculate_cost(
        self,
        model,
        input_tokens: int,
        output_tokens: int,
        label=None,
        force_calculation: bool = False,
    ) -> float:
        return calculate_model_cost(model, input_tokens, output_tokens)

    def process_interaction_cost(
        self,
        model,
        input_tokens: int,
        output_tokens: int,
        reasoning_tokens: int = 0,
        provided_cost=None,
        cache_hit_tokens: int = 0,
    ) -> float:
        """Update interaction-level counters and return USD cost.

        When cache_hit_tokens is provided (from DeepSeek's
        prompt_cache_hit_tokens response field), the calculation is
        accurate. Otherwise we charge full miss price for all input.
        """
        self.interaction_input_tokens = input_tokens
        self.interaction_output_tokens = output_tokens
        self.interaction_reasoning_tokens = reasoning_tokens
        if provided_cost is not None:
            cost = float(provided_cost)
        elif cache_hit_tokens:
            miss = max(input_tokens - cache_hit_tokens, 0)
            cost = calculate_cost_with_cache(model, miss, cache_hit_tokens, output_tokens)
        else:
            cost = calculate_model_cost(model, input_tokens, output_tokens)
        self.add_interaction_cost(cost)
        return cost

    def process_total_cost(
        self,
        model,
        total_input_tokens: int,
        total_output_tokens: int,
        total_reasoning_tokens: int = 0,
        provided_cost=None,
    ) -> float:
        self.current_agent_input_tokens = total_input_tokens
        self.current_agent_output_tokens = total_output_tokens
        self.current_agent_reasoning_tokens = total_reasoning_tokens
        if provided_cost is not None:
            self.current_agent_total_cost = float(provided_cost)
        else:
            self.current_agent_total_cost = calculate_model_cost(
                model, total_input_tokens, total_output_tokens
            )
        return self.current_agent_total_cost


def _parse_price_limit() -> float:
    """Read KRYON_PRICE_LIMIT env. Defaults to inf (no limit)."""
    raw = os.environ.get("KRYON_PRICE_LIMIT", "inf").strip().lower()
    if raw in ("inf", "infinity", "none", "", "unlimited"):
        return float("inf")
    try:
        return float(raw)
    except ValueError:
        return float("inf")


# Global instance — imported as kryon.util.COST_TRACKER everywhere.
COST_TRACKER = CostTracker()
