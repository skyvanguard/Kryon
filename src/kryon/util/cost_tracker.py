"""
Cost tracking utilities for KRYON — No-op stub.

KRYON uses local Ollama models (free), so cost tracking is unnecessary.
This module provides no-op implementations that maintain backward compatibility.
"""

import os
from dataclasses import dataclass, field
from typing import Optional


def get_model_name(model):
    """Extract a string model name from various model inputs."""
    if isinstance(model, str):
        return model
    return os.environ.get("KRYON_MODEL", "qwen3:8b")


def get_model_input_tokens(model):
    """Get max context window tokens for a model."""
    model_tokens = {
        "qwen3": 32000,
        "qwen2.5": 32000,
        "llama3.1": 32000,
        "gpt": 128000,
        "o1": 200000,
        "claude": 200000,
        "deepseek": 128000,
    }
    for model_type, tokens in model_tokens.items():
        if model_type in model:
            return tokens
    return 32000


def format_time(seconds):
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


@dataclass
class CostTracker:
    """No-op cost tracker — all costs are zero for local Ollama models."""

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

    def check_price_limit(self, new_cost: float) -> None:
        pass

    def update_session_cost(self, new_cost: float) -> None:
        pass

    def add_interaction_cost(self, new_cost: float) -> None:
        pass

    def reset_cost_for_local_model(self, model_name: str) -> bool:
        return True

    def reset_agent_costs(self) -> None:
        self.current_agent_input_tokens = 0
        self.current_agent_output_tokens = 0
        self.current_agent_reasoning_tokens = 0
        self.interaction_input_tokens = 0
        self.interaction_output_tokens = 0
        self.interaction_reasoning_tokens = 0

    def log_final_cost(self) -> None:
        pass

    def get_model_pricing(self, model_name: str) -> tuple:
        return (0.0, 0.0)

    def calculate_cost(self, model, input_tokens, output_tokens, label=None, force_calculation=False) -> float:
        return 0.0

    def process_interaction_cost(self, model, input_tokens, output_tokens, reasoning_tokens=0, provided_cost=None) -> float:
        self.interaction_input_tokens = input_tokens
        self.interaction_output_tokens = output_tokens
        self.interaction_reasoning_tokens = reasoning_tokens
        return 0.0

    def process_total_cost(self, model, total_input_tokens, total_output_tokens, total_reasoning_tokens=0, provided_cost=None) -> float:
        self.current_agent_input_tokens = total_input_tokens
        self.current_agent_output_tokens = total_output_tokens
        self.current_agent_reasoning_tokens = total_reasoning_tokens
        return 0.0


# Global instance
COST_TRACKER = CostTracker()


def get_model_pricing(model_name):
    """Get pricing for a model (always free for local models)."""
    return (0.0, 0.0)


def calculate_model_cost(model, input_tokens, output_tokens):
    """Calculate cost (always zero for local models)."""
    return 0.0
