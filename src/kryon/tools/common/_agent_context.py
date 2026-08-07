"""Agent token and context information utilities."""


def _get_agent_token_info():
    """Get current agent's token information from the active model instance."""
    # Try to get agent info from the current execution context
    try:
        from kryon.sdk.agents.models.openai_chatcompletions import get_current_active_model

        # First try to get the current active model (set during execution)
        model = get_current_active_model()

        if model:
            # Get display name with ID (e.g., "Red Team Agent [P1]")
            if hasattr(model, "get_full_display_name"):
                display_name = model.get_full_display_name()
            elif hasattr(model, "agent_name"):
                # Include [P1] only if we have a valid agent_id
                if hasattr(model, "agent_id") and model.agent_id:
                    display_name = f"{model.agent_name} [{model.agent_id}]"
                else:
                    # In single agent mode, just show the agent name without [P1]
                    display_name = model.agent_name
            else:
                display_name = "Agent"

            return {
                "agent_name": display_name,  # This now includes the ID
                "agent_id": getattr(model, "agent_id", None),
                "interaction_counter": getattr(model, "interaction_counter", 0),
                "total_input_tokens": getattr(model, "total_input_tokens", 0),
                "total_output_tokens": getattr(model, "total_output_tokens", 0),
                "total_reasoning_tokens": getattr(model, "total_reasoning_tokens", 0),
                "total_cost": getattr(model, "total_cost", 0.0),
            }

        # Fallback: Try to get from the most recent instance in the registry
        from kryon.sdk.agents.models.openai_chatcompletions import ACTIVE_MODEL_INSTANCES

        if ACTIVE_MODEL_INSTANCES:
            # Get the most recent instance (highest instance ID)
            latest_key = max(ACTIVE_MODEL_INSTANCES.keys(), key=lambda x: x[1])
            model_ref = ACTIVE_MODEL_INSTANCES[latest_key]
            model = model_ref() if model_ref else None

            if model:
                # Get display name with ID
                if hasattr(model, "get_full_display_name"):
                    display_name = model.get_full_display_name()
                elif hasattr(model, "agent_name"):
                    # Include [P1] only if we have a valid agent_id
                    if hasattr(model, "agent_id") and model.agent_id:
                        display_name = f"{model.agent_name} [{model.agent_id}]"
                    else:
                        # In single agent mode, just show the agent name without [P1]
                        display_name = model.agent_name
                else:
                    display_name = "Agent"

                return {
                    "agent_name": display_name,  # This now includes the ID
                    "agent_id": getattr(model, "agent_id", None),
                    "interaction_counter": getattr(model, "interaction_counter", 0),
                    "total_input_tokens": getattr(model, "total_input_tokens", 0),
                    "total_output_tokens": getattr(model, "total_output_tokens", 0),
                    "total_reasoning_tokens": getattr(model, "total_reasoning_tokens", 0),
                    "total_cost": getattr(model, "total_cost", 0.0),
                }
    except Exception:
        pass

    # Return default values if we can't get agent info
    return {
        "agent_name": "Agent",
        "agent_id": None,
        "interaction_counter": 0,
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "total_reasoning_tokens": 0,
        "total_cost": 0.0,
    }
