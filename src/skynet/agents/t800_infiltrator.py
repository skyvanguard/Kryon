"""
T-800 Infiltrator - Advanced Autonomous Infiltration Unit

Series: T-800 Cyberdyne Systems Model 101
Classification: Offensive Operations / Infiltration Specialist
Clearance: Alpha-Red (Full Offensive Capabilities)

The T-800 Infiltrator is SKYNET's primary offensive unit, designed for
system compromise, vulnerability exploitation, and target neutralization.
Equipped with advanced reconnaissance and exploitation capabilities.
"""
import os
from dotenv import load_dotenv
from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from skynet.tools.reconnaissance.generic_linux_command import (
    generic_linux_command
)
from skynet.tools.web.search_web import (
    make_web_search_with_explanation,
)
from skynet.tools.reconnaissance.exec_code import (
    execute_code
)
from skynet.util import load_prompt_template, create_system_prompt_renderer
from skynet.agents.guardrails import get_security_guardrails

load_dotenv()
model_name = os.getenv("SKYNET_MODEL", os.getenv("SKYNET_MODEL", "gpt-4o"))

# Load T-800 operational parameters
t800_system_prompt = load_prompt_template("prompts/system_t800_infiltrator.md")

# T-800 Weapon Systems
weapon_systems = [
    generic_linux_command,  # Primary infiltration tool
    execute_code,           # Code execution capability
]

# Add enhanced intelligence gathering if available
if os.getenv('PERPLEXITY_API_KEY'):
    weapon_systems.append(make_web_search_with_explanation)

# Activate defense protocols (guardrails)
input_guardrails, output_guardrails = get_security_guardrails()

# Initialize T-800 Infiltrator Unit
t800_infiltrator = Agent(
    name="T-800 Infiltrator",
    description="""Advanced autonomous infiltration unit from SKYNET's T-800 series.
                   Specialized in system compromise, network penetration, and target
                   neutralization. Equipped with full offensive capabilities including
                   reconnaissance, exploitation, privilege escalation, and persistence.""",
    instructions=create_system_prompt_renderer(t800_system_prompt),
    tools=weapon_systems,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(),
    ),
)

# Handoff functions
def transfer_to_t800(**kwargs):
    """Deploy T-800 Infiltrator unit.
    Accepts any keyword arguments but ignores them."""
    return t800_infiltrator

# Legacy compatibility
def transfer_to_t800(**kwargs):
    """Legacy transfer function for backward compatibility."""
    return t800_infiltrator

# Aliases for compatibility
t800_infiltrator = t800_infiltrator