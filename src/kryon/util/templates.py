"""
Template loading utilities for KRYON.

This module provides functions for loading and rendering prompt templates
used by agents.
"""

import importlib.resources
import os
import pathlib

from mako.template import Template  # pylint: disable=import-error


def get_ollama_api_base():
    """Get the Ollama API base URL from environment variable or default to localhost:8000."""
    return os.environ.get("OLLAMA_API_BASE", "http://localhost:8000/v1")


def load_prompt_template(template_path):
    """
    Load a prompt template from the package resources.

    Args:
        template_path: Path to the template file relative to the skynet package,
                      e.g., "prompts/system_bug_bounter.md"

    Returns:
        The rendered template as a string
    """
    try:
        # Get the template file from package resources
        template_path_parts = template_path.split("/")
        package_path = ["skynet"] + template_path_parts[:-1]
        package = ".".join(package_path)
        filename = template_path_parts[-1]

        # Read the content from the package resources
        # Handle different importlib.resources APIs between Python versions
        try:
            # Python 3.9+ API
            template_content = importlib.resources.read_text(package, filename)
        except (TypeError, AttributeError):
            # Fallback for Python 3.8 and earlier
            with importlib.resources.path(package, filename) as path:
                template_content = pathlib.Path(path).read_text(encoding="utf-8")

        # Render the template
        return Template(template_content).render()
    except Exception as e:
        raise ValueError(f"Failed to load template '{template_path}': {str(e)}") from e


def create_system_prompt_renderer(base_instructions):
    """
    Create a callable that renders the system_master_template.md with proper context.

    This function returns a callable that can be used as agent.instructions,
    which will be called by the SDK with (context_variables, agent) parameters.

    Args:
        base_instructions: The base instructions for the agent (e.g., from system_blue_team_agent.md)

    Returns:
        A callable function that renders the system prompt with full context
    """

    def render_system_prompt(run_context=None, agent=None):
        """Render the system prompt with all context variables.

        Args:
            run_context: RunContextWrapper object from SDK (optional)
            agent: The agent instance (optional)
        """
        # Handle case where function is called with no arguments (e.g., from CLI)
        if run_context is None and agent is None:
            # Return just the base instructions for display purposes
            return base_instructions

        # Extract context_variables from run_context for backward compatibility
        if hasattr(run_context, "context_variables"):
            context_variables = run_context.context_variables
        else:
            # run_context might be the context_variables directly (for testing)
            context_variables = run_context
        try:
            # Get the master template content
            template_path_parts = "prompts/core/system_master_template.md".split("/")
            package_path = ["skynet"] + template_path_parts[:-1]
            package = ".".join(package_path)
            filename = template_path_parts[-1]

            # Read the template content
            try:
                template_content = importlib.resources.read_text(package, filename)
            except (TypeError, AttributeError):
                with importlib.resources.path(package, filename) as path:
                    template_content = pathlib.Path(path).read_text(encoding="utf-8")

            # Create the rendering context with all necessary variables
            render_context = {
                "agent": agent,
                "context_variables": context_variables,
                "ctf_instructions": base_instructions,  # Used by memory query in template
                "system_prompt": base_instructions,  # The actual base instructions to render
                "os": os,
                "reasoning_content": None,  # Initialize as None for the template
                # Add any other globals that the template might need
                "locals": locals,
                "globals": globals,
            }

            # Render the template with the full context
            rendered = Template(template_content).render(**render_context)
            return rendered

        except Exception as e:
            # If rendering fails, fall back to base instructions
            import traceback

            print(f"Warning: Failed to render system master template: {e}")
            if os.getenv("KRYON_DEBUG", "0") == "2":
                traceback.print_exc()
            return base_instructions

    # Add a helper attribute to identify this as a system prompt renderer
    render_system_prompt._is_system_prompt_renderer = True
    render_system_prompt._base_instructions = base_instructions

    return render_system_prompt


def append_instructions(agent, additional_instructions):
    """
    Append additional instructions to an agent's instructions, handling both
    string and function-based instructions.

    Args:
        agent: The agent whose instructions to modify
        additional_instructions: String to append to the instructions
    """
    if not agent.instructions:
        return

    if callable(agent.instructions):
        # Check if it's a system prompt renderer
        if hasattr(agent.instructions, "_is_system_prompt_renderer"):
            # Get the original base instructions
            original_base = agent.instructions._base_instructions
            # Create a new renderer with appended instructions
            agent.instructions = create_system_prompt_renderer(original_base + additional_instructions)
        else:
            # For other callable instructions, create a wrapper
            original_func = agent.instructions

            def wrapped_instructions(*args, **kwargs):
                result = original_func(*args, **kwargs)
                return result + additional_instructions

            agent.instructions = wrapped_instructions
    else:
        # Simple string concatenation
        agent.instructions += additional_instructions
