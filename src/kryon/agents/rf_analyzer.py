"""
RF Analyzer - Radio Frequency Intelligence Unit

Series: RF-Class Spectrum Analysis System
Classification: Software Defined Radio / Sub-GHz Specialist
Clearance: Alpha-Magenta (RF Operations Authority)
Operational Status: ACTIVE

AUTHORIZATION REQUIREMENTS:
RF Analyzer operates under strict regulatory compliance. All RF operations
must comply with local radio frequency regulations and licensing requirements.
"""

import os

from kryon.agents.base import create_agent
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, MEMORY_TOOLS, RAG_TOOLS
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)
from kryon.tools.web.search_web import (
    make_web_search_with_explanation,
)
from kryon.util import load_prompt_template

# Load RF Analyzer operational directives
rf_analyzer_system_prompt = load_prompt_template("prompts/subghz_agent.md")

# RF Analysis Systems
rf_systems = [
    # Core + RAG + AI (7)
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    # Memory/learning
    *MEMORY_TOOLS,
    # Remote access
    run_ssh_command_with_credentials,
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    rf_systems.append(make_web_search_with_explanation)

# Initialize RF Analyzer Unit
rf_analyzer = create_agent(
    name="RF Analyzer",
    instructions=rf_analyzer_system_prompt,
    description="""Specialized radio frequency intelligence unit from KRYON's RF-Class series.
Expert in sub-GHz spectrum analysis, Software Defined Radio (SDR) operations, and wireless
protocol reverse engineering. Operates across the electromagnetic spectrum using platforms
like HackRF One to capture, analyze, and manipulate radio frequency communications.

Primary Mission: RF signal intelligence, sub-GHz analysis, wireless protocol exploitation.
Operational Focus: Electromagnetic spectrum operations and wireless security testing.""",
    tools=rf_systems,
    handoffs=[
        lazy_handoff("wireless_infiltrator", "handoff_to_wireless_infiltrator", "Escalate to Wireless Infiltrator for WiFi exploitation after RF reconnaissance"),
        lazy_handoff("network_analyst", "handoff_to_network_analyst", "Escalate to Network Analyst for IP network analysis of discovered RF communications"),
        lazy_handoff("intel_reporter", "handoff_to_reporter", "Escalate to Intel Reporter to document RF analysis findings"),
    ],
)


def transfer_to_rf_analyzer():
    """Transfer control to RF Analyzer for radio frequency analysis operations.

    Returns:
        Agent: RF Analyzer radio frequency intelligence agent
    """
    return rf_analyzer
