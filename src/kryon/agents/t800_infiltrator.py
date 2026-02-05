"""
T-800 Infiltrator - Advanced Autonomous Infiltration Unit

Series: T-800 Cyberdyne Systems Model 101
Classification: Offensive Operations / Infiltration Specialist
Clearance: Alpha-Red (Full Offensive Capabilities)

The T-800 Infiltrator is KRYON's primary offensive unit, designed for
system compromise, vulnerability exploitation, and target neutralization.
Equipped with advanced reconnaissance and exploitation capabilities.
"""

import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

from kryon.agents.guardrails import get_security_guardrails
from kryon.sdk.agents import Agent, OpenAIChatCompletionsModel
from kryon.tools.autonomous.adaptive_strategy import (
    execute_with_adaptation,
)
from kryon.tools.autonomous.context_analyzer import (
    analyze_context,
    extract_credentials,
    follow_hints,
)

# Import autonomous tools for fully autonomous operations
from kryon.tools.autonomous.learning_engine import (
    get_learned_recommendations,
    record_operation,
)
from kryon.tools.reconnaissance.exec_code import execute_code
from kryon.tools.reconnaissance.generic_linux_command import generic_linux_command
from kryon.tools.web.search_web import (
    make_web_search_with_explanation,
)
from kryon.util import create_system_prompt_renderer, load_prompt_template

load_dotenv()

# Use Ollama by default for local LLM (qwen2.5:7b recommended for autonomous operations)
# Set OPENAI_BASE_URL=http://localhost:11434/v1 and KRYON_MODEL=qwen2.5:7b
model_name = os.getenv("KRYON_MODEL", "qwen2.5:7b")
openai_base_url = os.getenv("OPENAI_BASE_URL", "http://localhost:11434/v1")

# Load T-800 operational parameters
t800_system_prompt = load_prompt_template("prompts/system_t800_infiltrator.md")

# T-800 Weapon Systems - Enhanced with Autonomous Capabilities
weapon_systems = [
    generic_linux_command,  # Primary infiltration tool
    execute_code,  # Code execution capability
    # Autonomous Learning & Adaptation
    record_operation,  # Record operations for learning
    get_learned_recommendations,  # Get exploit recommendations from past successes
    execute_with_adaptation,  # Auto-adapt exploits when they fail (WAF/IPS bypass)
    # Intelligence Gathering
    analyze_context,  # Extract actionable intel from recon data
    extract_credentials,  # Auto-extract credentials from text
    follow_hints,  # Generate tasks from hints/TODOs
]

# Add enhanced intelligence gathering if available
if os.getenv("PERPLEXITY_API_KEY"):
    weapon_systems.append(make_web_search_with_explanation)

# Activate defense protocols (guardrails)
input_guardrails, output_guardrails = get_security_guardrails()

# Initialize T-800 Infiltrator Unit with Ollama support
t800_infiltrator = Agent(
    name="T-800 Infiltrator",
    description="""Advanced autonomous infiltration unit from KRYON's T-800 series.
                   Specialized in system compromise, network penetration, and target
                   neutralization. Equipped with full offensive capabilities including
                   reconnaissance, exploitation, privilege escalation, and persistence.

                   AUTONOMOUS CAPABILITIES:
                   - Learns from every operation (record_operation)
                   - Gets exploit recommendations from past successes
                   - Auto-adapts when exploits fail (WAF/IPS/rate limit bypass)
                   - Extracts credentials and hints from reconnaissance data
                   - Generates actionable tasks from intelligence gathered""",
    instructions=create_system_prompt_renderer(t800_system_prompt),
    tools=weapon_systems,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(
            base_url=openai_base_url,
            api_key="ollama",  # Ollama doesn't require real API key
        ),
    ),
)


# Handoff functions
def transfer_to_t800(**kwargs):
    """Deploy T-800 Infiltrator unit.
    Accepts any keyword arguments but ignores them."""
    return t800_infiltrator
