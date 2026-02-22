"""
Cost tracking utilities for KRYON.

This module provides:
- CostTracker class for tracking API costs across sessions
- Helper functions for model pricing and cost calculation
"""

import atexit
import json
import os
import pathlib
from dataclasses import dataclass, field
from typing import Optional


def get_model_name(model):
    """
    Extract a string model name from various model inputs.

    Centralizes model name standardization to avoid inconsistencies
    (e.g. avoid passing model object instead of string name).

    Args:
        model: String model name or model object

    Returns:
        str: Standardized model name string
    """
    if isinstance(model, str):
        return model
    # If not a string, use environment variable
    return os.environ.get("KRYON_MODEL", "gpt-4o")


def get_model_input_tokens(model):
    """
    Get the number of input tokens for
    max context window capacity for a given model.
    """
    model_tokens = {
        "gpt": 128000,
        "o1": 200000,
        "claude": 200000,
        "qwen2.5": 32000,  # https://ollama.com/library/qwen2.5, 128K input, 8K output
        "llama3.1": 32000,  # https://ollama.com/library/llama3.1, 128K input
        "deepseek": 128000,  # https://api-docs.deepseek.com/quick_start/pricing
    }
    for model_type, tokens in model_tokens.items():
        if model_type in model:
            return tokens
    return model_tokens["gpt"]


def format_time(seconds):
    """Helper function to format time in a human-readable way."""
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
    """Shared stats tracking object to maintain consistent costs across calls."""

    # Session-level stats
    session_total_cost: float = 0.0

    # Current agent stats
    current_agent_total_cost: float = 0.0
    current_agent_input_tokens: int = 0
    current_agent_output_tokens: int = 0
    current_agent_reasoning_tokens: int = 0

    # Current interaction stats
    interaction_input_tokens: int = 0
    interaction_output_tokens: int = 0
    interaction_reasoning_tokens: int = 0
    interaction_cost: float = 0.0

    # Calculation cache
    model_pricing_cache: dict[str, tuple] = field(default_factory=dict)
    calculated_costs_cache: dict[str, float] = field(default_factory=dict)

    # Track the last calculation to debug inconsistencies
    last_interaction_cost: float = 0.0
    last_total_cost: float = 0.0

    def check_price_limit(self, new_cost: float) -> None:
        """Check if adding the new cost would exceed the price limit."""
        from kryon.sdk.agents.exceptions import PriceLimitExceeded

        price_limit_env = os.getenv("KRYON_PRICE_LIMIT")
        try:
            price_limit = float(price_limit_env) if price_limit_env is not None else float("inf")
        except ValueError:
            price_limit = float("inf")

        if price_limit != float("inf"):
            total_cost = self.session_total_cost + new_cost
            if total_cost > price_limit:
                raise PriceLimitExceeded(total_cost, price_limit)

    def update_session_cost(self, new_cost: float) -> None:
        """Add cost to session total and log the update"""
        # Check price limit before updating
        self.check_price_limit(new_cost)

        self.session_total_cost += new_cost

    def add_interaction_cost(self, new_cost: float) -> None:
        """
        Add an interaction cost to the session total and check price limit.
        This is a convenience method that combines check_price_limit and update_session_cost.
        """
        # Skip updating costs if the cost is zero (common with local models)
        if new_cost <= 0:
            self.last_interaction_cost = 0.0
            return

        # Check price limit first
        self.check_price_limit(new_cost)

        # Then update the session cost
        self.session_total_cost += new_cost

        # Update the last interaction cost for tracking
        self.last_interaction_cost = new_cost

    def reset_cost_for_local_model(self, model_name: str) -> bool:
        """
        Reset interaction cost tracking when switching to a local model.
        Returns True if the model was identified as local and cost was reset.
        """
        # Check if this is a local/free model by getting its pricing
        input_cost, output_cost = self.get_model_pricing(model_name)

        # If both costs are zero, it's a free/local model
        if input_cost == 0.0 and output_cost == 0.0:
            # Reset the current interaction costs but keep total session costs
            self.interaction_cost = 0.0
            self.last_interaction_cost = 0.0
            # Don't reset session_total_cost as that includes previous paid models
            return True

        return False

    def reset_agent_costs(self) -> None:
        """
        Reset costs for a new agent run.
        This should be called when starting a new agent to avoid inheriting previous agent's costs.
        """
        # Reset current agent stats
        self.current_agent_total_cost = 0.0
        self.current_agent_input_tokens = 0
        self.current_agent_output_tokens = 0
        self.current_agent_reasoning_tokens = 0

        # Reset current interaction stats
        self.interaction_input_tokens = 0
        self.interaction_output_tokens = 0
        self.interaction_reasoning_tokens = 0
        self.interaction_cost = 0.0

        # Reset tracking variables
        self.last_interaction_cost = 0.0
        self.last_total_cost = 0.0

    def log_final_cost(self) -> None:
        """Display final cost information at exit"""
        # Skip displaying cost if already shown in the session summary
        if os.environ.get("KRYON_COST_DISPLAYED", "").lower() == "true":
            return
        print(f"\nTotal KRYON Session Cost: ${self.session_total_cost:.6f}")

    def get_model_pricing(self, model_name: str) -> tuple:
        """Get and cache pricing information for a model"""
        # Use the centralized function to standardize model names
        model_name = get_model_name(model_name)

        # Check cache first
        if model_name in self.model_pricing_cache:
            return self.model_pricing_cache[model_name]

        # Try to load pricing from local pricing.json first
        # Only use if the specific model name exists in the file
        try:
            pricing_path = pathlib.Path("pricing.json")
            if pricing_path.exists():
                with open(pricing_path, encoding="utf-8") as f:
                    local_pricing = json.load(f)
                    # Only use pricing if the exact model name exists in the file
                    if model_name in local_pricing:
                        pricing_info = local_pricing[model_name]
                        input_cost = pricing_info.get("input_cost_per_token", 0)
                        output_cost = pricing_info.get("output_cost_per_token", 0)

                        # Cache and return local pricing
                        self.model_pricing_cache[model_name] = (input_cost, output_cost)
                        return input_cost, output_cost
        except Exception as e:
            print(f"  WARNING: Error loading local pricing.json: {str(e)}")

        # Fallback to LiteLLM API if local pricing not found
        LITELLM_URL = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"

        try:
            import requests

            response = requests.get(LITELLM_URL, timeout=2)
            if response.status_code == 200:
                model_pricing_data = response.json()

                # Get pricing info for the model
                pricing_info = model_pricing_data.get(model_name, {})
                input_cost_per_token = pricing_info.get("input_cost_per_token", 0)
                output_cost_per_token = pricing_info.get("output_cost_per_token", 0)

                # Cache the results
                self.model_pricing_cache[model_name] = (input_cost_per_token, output_cost_per_token)
                return input_cost_per_token, output_cost_per_token
        except Exception as e:
            # Check if it's a network connectivity issue by testing a simple connection
            try:
                import requests

                requests.get("https://google.com/", timeout=1)
                # The pricing URL failed
                print(f"  WARNING: Error fetching model pricing: {str(e)}")
            except Exception:
                # No internet connection, silently skip the warning
                pass

        # Default to zero cost if no pricing found (local/free models)
        default_pricing = (0.0, 0.0)
        self.model_pricing_cache[model_name] = default_pricing
        return default_pricing

    def calculate_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        label: Optional[str] = None,
        force_calculation: bool = False,
    ) -> float:
        """Calculate and cache cost for a given model and token counts"""
        # Standardize model name using the central function
        model_name = get_model_name(model)

        # Generate a cache key
        cache_key = f"{model_name}_{input_tokens}_{output_tokens}"

        # Return cached result if available (unless force_calculation is True)
        if cache_key in self.calculated_costs_cache and not force_calculation:
            return self.calculated_costs_cache[cache_key]

        # First, try to use litellm's completion_cost method
        try:
            import litellm

            # Create a mock response with usage data for litellm.completion_cost
            mock_response = {
                "model": model_name,
                "usage": {
                    "prompt_tokens": input_tokens,
                    "completion_tokens": output_tokens,
                    "total_tokens": input_tokens + output_tokens,
                },
            }

            # Try to get cost from litellm
            litellm_cost = litellm.completion_cost(completion_response=mock_response)

            # If litellm returns a non-zero cost, use it
            if litellm_cost > 0:
                self.calculated_costs_cache[cache_key] = litellm_cost
                return litellm_cost
        except Exception:
            # If litellm fails or is not available, continue to fallback
            pass

        # Fallback to our pricing.json method
        # Get pricing information
        input_cost_per_token, output_cost_per_token = self.get_model_pricing(model_name)

        # Calculate costs - use high precision for calculations
        input_cost = input_tokens * input_cost_per_token
        output_cost = output_tokens * output_cost_per_token
        total_cost = input_cost + output_cost

        # Cache the result with full precision
        self.calculated_costs_cache[cache_key] = total_cost

        return total_cost

    def process_interaction_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        reasoning_tokens: int = 0,
        provided_cost: Optional[float] = None,
    ) -> float:
        """Process and track costs for a new interaction"""
        # Standardize model name
        model_name = get_model_name(model)

        # Update token counts
        self.interaction_input_tokens = input_tokens
        self.interaction_output_tokens = output_tokens
        self.interaction_reasoning_tokens = reasoning_tokens

        # Use provided cost or calculate
        if provided_cost is not None and provided_cost > 0:
            self.interaction_cost = float(provided_cost)
        else:
            self.interaction_cost = self.calculate_cost(
                model_name, input_tokens, output_tokens, label="OFFICIAL CALCULATION: Interaction"
            )

        self.last_interaction_cost = self.interaction_cost

        return self.interaction_cost

    def process_total_cost(
        self,
        model: str,
        total_input_tokens: int,
        total_output_tokens: int,
        total_reasoning_tokens: int = 0,
        provided_cost: Optional[float] = None,
    ) -> float:
        """Process and track costs for total (cumulative) usage"""
        # Standardize model name
        model_name = get_model_name(model)

        # Update token counts
        self.current_agent_input_tokens = total_input_tokens
        self.current_agent_output_tokens = total_output_tokens
        self.current_agent_reasoning_tokens = total_reasoning_tokens

        # If a total cost is explicitly provided, use it directly
        if provided_cost is not None and provided_cost > 0:
            new_total_cost = float(provided_cost)
        else:
            # Calculate the total cost from all tokens
            new_total_cost = self.calculate_cost(
                model_name, total_input_tokens, total_output_tokens, label="TOTAL COST CALCULATION"
            )

        # Calculate the difference from the previous total to get this interaction's cost
        previous_total = self.current_agent_total_cost
        cost_diff = new_total_cost - previous_total

        # Only add to session total if there's genuinely new cost (and it's positive)
        if cost_diff > 0:
            self.update_session_cost(cost_diff)
            actual_cost_added = cost_diff
        else:
            actual_cost_added = 0

        # Update the current agent's total cost
        self.current_agent_total_cost = new_total_cost

        # Return the actual cost that was added to the session
        return actual_cost_added

        # Track the last total for debugging
        self.last_total_cost = new_total_cost

        # Return the new total cost (keep backward compatibility)
        # But the actual incremental cost is tracked above
        return new_total_cost


# Initialize the global cost tracker
COST_TRACKER = CostTracker()

# Register exit handler for final cost display
atexit.register(COST_TRACKER.log_final_cost)


def get_model_pricing(model_name):
    """
    Get pricing information for a model, using the CostTracker's implementation.
    This is a global helper that delegates to the CostTracker instance.

    Args:
        model_name: String name of the model

    Returns:
        tuple: (input_cost_per_token, output_cost_per_token)
    """
    # Standardize model name
    model_name = get_model_name(model_name)

    # Use the CostTracker's implementation to maintain consistency and use its cache
    return COST_TRACKER.get_model_pricing(model_name)


def calculate_model_cost(model, input_tokens, output_tokens):
    """
    Calculate the cost for a given model based on token usage.

    Args:
        model: The model name or object
        input_tokens: Number of input tokens used
        output_tokens: Number of output tokens used

    Returns:
        float: The calculated cost in dollars
    """
    # Use the CostTracker to handle duplicates
    return COST_TRACKER.calculate_cost(
        model,
        input_tokens,
        output_tokens,
        label="COST CALCULATION",
        force_calculation=False,  # Let it use the cache for duplicates
    )
