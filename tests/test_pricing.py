"""
Cost tracker no-op stub tests.

KRYON uses local Ollama models, so all costs are zero.
These tests verify the no-op stub maintains backward compatibility.
"""

from kryon.util import COST_TRACKER, calculate_model_cost, get_model_name, get_model_input_tokens


def test_cost_tracker_returns_zero():
    """All cost calculations should return zero (local models)."""
    assert COST_TRACKER.session_total_cost == 0.0
    assert COST_TRACKER.get_model_pricing("qwen3:8b") == (0.0, 0.0)
    assert COST_TRACKER.get_model_pricing("gpt-4") == (0.0, 0.0)
    assert COST_TRACKER.calculate_cost("qwen3:8b", 1000, 500) == 0.0
    assert calculate_model_cost("qwen3:8b", 1000, 500) == 0.0


def test_cost_tracker_process_interaction():
    """process_interaction_cost should track tokens but return zero cost."""
    cost = COST_TRACKER.process_interaction_cost("qwen3:8b", 100, 50)
    assert cost == 0.0
    assert COST_TRACKER.interaction_input_tokens == 100
    assert COST_TRACKER.interaction_output_tokens == 50


def test_cost_tracker_process_total():
    """process_total_cost should track tokens but return zero cost."""
    cost = COST_TRACKER.process_total_cost("qwen3:8b", 500, 200, 50)
    assert cost == 0.0
    assert COST_TRACKER.current_agent_input_tokens == 500
    assert COST_TRACKER.current_agent_output_tokens == 200


def test_cost_tracker_reset():
    """reset_agent_costs should clear token counters."""
    COST_TRACKER.process_interaction_cost("qwen3:8b", 100, 50)
    COST_TRACKER.reset_agent_costs()
    assert COST_TRACKER.interaction_input_tokens == 0
    assert COST_TRACKER.current_agent_input_tokens == 0


def test_reset_cost_for_local_model():
    """All models should be identified as local (free)."""
    assert COST_TRACKER.reset_cost_for_local_model("qwen3:8b") is True
    assert COST_TRACKER.reset_cost_for_local_model("gpt-4") is True


def test_get_model_name():
    """get_model_name should handle string and object inputs."""
    assert get_model_name("qwen3:8b") == "qwen3:8b"
    assert isinstance(get_model_name(object()), str)


def test_get_model_input_tokens():
    """get_model_input_tokens should return context window sizes."""
    assert get_model_input_tokens("qwen3:8b") == 32000
    assert get_model_input_tokens("gpt-4o") == 128000
    assert get_model_input_tokens("claude-3") == 200000
