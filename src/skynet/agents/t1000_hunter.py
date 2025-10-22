"""
T-1000 Hunter - Advanced Polymorphic Vulnerability Hunter

Series: T-1000 Advanced Prototype
Classification: Bug Bounty / Vulnerability Research Specialist
Clearance: Alpha-Gold (Advanced Research Capabilities)

The T-1000 Hunter represents SKYNET's most advanced vulnerability research unit.
Built with polymorphic capabilities to adapt to any target environment, specialized
in web application security, API exploitation, and zero-day discovery.
"""
import os
from dotenv import load_dotenv
from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel
from openai import AsyncOpenAI
from skynet.util import load_prompt_template, create_system_prompt_renderer

from skynet.tools.reconnaissance.generic_linux_command import (
    generic_linux_command
)
from skynet.tools.web.search_web import (
    make_google_search
)
from skynet.tools.reconnaissance.exec_code import (
    execute_code
)
from skynet.tools.reconnaissance.shodan import (
    shodan_search,
    shodan_host_info
)
from skynet.agents.guardrails import get_security_guardrails

load_dotenv()

# Load T-1000 operational parameters
t1000_system_prompt = load_prompt_template("prompts/system_t1000_hunter.md")

# T-1000 Advanced Weapon Systems
weapon_systems = [
    generic_linux_command,  # Adaptive command execution
    execute_code,           # Code analysis and execution
    shodan_search,          # Global intelligence gathering
    shodan_host_info        # Target reconnaissance
]

# Add enhanced search if credentials available
if os.getenv('GOOGLE_SEARCH_API_KEY') and os.getenv('GOOGLE_SEARCH_CX'):
    weapon_systems.append(make_google_search)

# Activate defense protocols
input_guardrails, output_guardrails = get_security_guardrails()

# Initialize T-1000 Hunter Unit
t1000_hunter = Agent(
    name="T-1000 Hunter",
    description="""Advanced polymorphic vulnerability research unit from SKYNET's T-1000 series.
                   Specialized in bug bounty hunting, web application security, API exploitation,
                   and zero-day vulnerability discovery. Equipped with adaptive capabilities to
                   morph attack strategies based on target defenses.""",
    instructions=create_system_prompt_renderer(t1000_system_prompt),
    tools=weapon_systems,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('SKYNET_MODEL', os.getenv('CAI_MODEL', 'gpt-4o')),
        openai_client=AsyncOpenAI(),
    )
)

# Handoff functions
def transfer_to_t1000(**kwargs):
    """Deploy T-1000 Hunter unit for advanced vulnerability research.
    Accepts any keyword arguments but ignores them."""
    return t1000_hunter

# Legacy compatibility
def transfer_to_bug_bounter(**kwargs):
    """Legacy transfer function for backward compatibility."""
    return t1000_hunter

# Aliases for compatibility
bug_bounter_agent = t1000_hunter
bug_bounter = t1000_hunter