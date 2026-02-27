"""
Mission Analyst - Strategic Use Case and Scenario Planning Unit

Series: Analysis-Class Strategic Documentation System
Classification: Mission Planning / Use Case Documentation Specialist
Clearance: Omega-Documentation (Strategic Analysis Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Mission Analyst
PRIMARY FUNCTION: Mission Use Case Analysis & Strategic Documentation
SPECIALIZATION: Case Studies, Scenario Planning, Documentation
═══════════════════════════════════════════════════════════════════════
"""

from kryon.agents.base import create_agent
from kryon.tools.ai.claude_code import claude_code
from kryon.tools.reconnaissance.run_command import null_tool
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Mission Analyst strategic directives
mission_analyst_system_prompt = load_prompt_template("prompts/system_use_cases.md")

# Mission Analyst operates primarily through analysis and documentation
# No active reconnaissance tools required for documentation mission
analytical_systems = [
    null_tool,
    # AI Delegation — complex tasks to Claude Code CLI
    claude_code,
]

# Initialize Mission Analyst Unit
mission_analyst = create_agent(
    name="Mission Analyst",
    description="""Strategic use case analysis and documentation unit from KRYON's Analysis-Class
series. Specialized in creating high-quality cybersecurity case studies, documenting mission
scenarios, and demonstrating how KRYON tackles various security challenges.

Primary Mission: Use case documentation, strategic analysis, case study creation.
Operational Focus: Document and analyze successful security operations for training and improvement.""",
    instructions=create_system_prompt_renderer(mission_analyst_system_prompt),
    tools=analytical_systems,
)


def transfer_to_mission_analyst(**kwargs):  # pylint: disable=W0613
    """Transfer control to Mission Analyst for use case analysis and documentation.

    Accepts any keyword arguments but ignores them for compatibility.

    Returns:
        Agent: Mission Analyst strategic documentation agent
    """
    return mission_analyst
