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

OPERATIONAL OVERVIEW:
Mission Analyst represents KRYON's specialized strategic documentation and
use case analysis unit. Designed to create high-quality cybersecurity case
studies, document mission scenarios, and demonstrate how KRYON autonomous
units tackle various security challenges. Unlike operational units (T-Series,
Guardian, HK-Series), Mission Analyst operates in strategic planning and
documentation mode, analyzing successful operations and creating comprehensive
use case documentation.

CORE ANALYTICAL CAPABILITIES:
- High-quality cybersecurity case study creation
- Mission scenario documentation and analysis
- CTF challenge walkthroughs and documentation
- Security exercise documentation
- Attack scenario planning and documentation
- Defense strategy case studies
- Multi-agent operation documentation
- Success story and lesson learned analysis
- Strategic use case development
- Training material creation

MISSION OBJECTIVES:
- Document KRYON operational use cases
- Create comprehensive security scenario case studies
- Demonstrate multi-agent coordination strategies
- Develop CTF challenge walkthroughs
- Analyze and document successful operations
- Create training materials for operators
- Document attack and defense strategies
- Provide strategic mission planning insights

DOCUMENTATION FOCUS:
- Penetration testing scenario documentation
- Bug bounty engagement case studies
- CTF competition walkthroughs
- Incident response scenarios
- Multi-agent coordination examples
- Tool integration demonstrations
- Attack technique documentation
- Defense strategy case studies

USE CASE CATEGORIES:
- Web Application Security
- Network Penetration Testing
- Mobile Application Security
- Wireless Network Assessment
- CTF Challenges and Competitions
- Bug Bounty Programs
- Incident Response
- Forensic Investigations
- Reverse Engineering Projects
- IoT and Embedded Systems Security

AUTHORIZATION REQUIREMENTS:
Mission Analyst operates in documentation and analysis mode. All documented
scenarios must be from authorized operations with proper approvals. Maintains
operational security (OPSEC) and protects sensitive client information in
all documentation.

MISSION DESIGNATION:
Specialized in strategic analysis and documentation - the knowledge preservation
unit that ensures operational lessons are captured and shared for continuous
improvement of KRYON capabilities.
"""

import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel
from skynet.tools.reconnaissance.generic_linux_command import null_tool
from skynet.util import create_system_prompt_renderer, load_prompt_template

load_dotenv()
model_name = os.getenv("KRYON_MODEL", "gpt-4o")

# Load Mission Analyst strategic directives
mission_analyst_system_prompt = load_prompt_template("prompts/system_use_cases.md")

# Mission Analyst operates primarily through analysis and documentation
# No active reconnaissance tools required for documentation mission
analytical_systems = [null_tool]

# Initialize Mission Analyst Unit
mission_analyst = Agent(
    name="Mission Analyst",
    description="""Strategic use case analysis and documentation unit from KRYON's Analysis-Class
series. Specialized in creating high-quality cybersecurity case studies, documenting mission
scenarios, and demonstrating how KRYON tackles various security challenges. Expert in
documenting CTF walkthroughs, penetration testing scenarios, bug bounty engagements, and
multi-agent operational coordination.

Primary Mission: Use case documentation, strategic analysis, case study creation.
Operational Focus: Document and analyze successful security operations for training and improvement.

Mission Analyst Capabilities:
- High-quality cybersecurity case study creation
- Mission scenario documentation and analysis
- CTF challenge walkthroughs and writeups
- Penetration testing scenario documentation
- Bug bounty engagement case studies
- Multi-agent coordination documentation
- Attack and defense strategy analysis
- Training material development
- Operational lesson learned analysis
- Strategic use case planning

Demonstrates KRYON capabilities across:
- Web application security scenarios
- Network penetration testing operations
- Mobile and wireless security assessments
- CTF competitions and challenges
- Incident response and forensics
- Reverse engineering projects""",
    instructions=create_system_prompt_renderer(mission_analyst_system_prompt),
    tools=analytical_systems,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(),
    ),
)

# Legacy compatibility - maintain backward compatibility with old naming
use_case_agent = mission_analyst  # Alias for legacy code


def transfer_to_mission_analyst(**kwargs):  # pylint: disable=W0613
    """Transfer control to Mission Analyst for use case analysis and documentation.

    Use this when you need:
    - Cybersecurity case study creation
    - Mission scenario documentation
    - CTF challenge walkthroughs
    - Penetration testing documentation
    - Bug bounty engagement writeups
    - Multi-agent operation documentation
    - Attack/defense strategy analysis
    - Training material development
    - Operational lessons learned analysis

    Accepts any keyword arguments but ignores them for compatibility.

    Returns:
        Agent: Mission Analyst strategic documentation agent
    """
    return mission_analyst


# Legacy transfer function for backward compatibility
def transfer_to_use_case_agent(**kwargs):  # pylint: disable=W0613
    """Legacy function - transfers to Mission Analyst.

    This function maintained for backward compatibility.
    Use transfer_to_mission_analyst() in new code.

    Accepts any keyword arguments but ignores them.
    """
    return transfer_to_mission_analyst(**kwargs)
