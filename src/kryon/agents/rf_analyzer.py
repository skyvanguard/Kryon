"""
RF Analyzer - Radio Frequency Intelligence Unit

Series: RF-Class Spectrum Analysis System
Classification: Software Defined Radio / Sub-GHz Specialist
Clearance: Alpha-Magenta (RF Operations Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: RF Analyzer
PRIMARY FUNCTION: Radio Frequency Analysis & Signal Intelligence
SPECIALIZATION: Sub-GHz SDR, Protocol Analysis, Signal Capture/Replay
═══════════════════════════════════════════════════════════════════════

AUTHORIZATION REQUIREMENTS:
RF Analyzer operates under strict regulatory compliance. All RF operations
must comply with local radio frequency regulations and licensing requirements.
"""

import os

from kryon.agents.base import create_agent
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)
from kryon.tools.reconnaissance.exec_code import (
    execute_code,
)
from kryon.tools.reconnaissance.generic_linux_command import (
    generic_linux_command,
)
from kryon.tools.web.search_web import (
    make_web_search_with_explanation,
)
from kryon.util import load_prompt_template

# Load RF Analyzer operational directives
rf_analyzer_system_prompt = load_prompt_template("prompts/subghz_agent.md")

# RF Analysis Systems - Available SDR and spectrum analysis tools
rf_systems = [
    generic_linux_command,  # System operations for SDR tools
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,  # Script execution for RF analysis automation
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
)


def transfer_to_rf_analyzer():
    """Transfer control to RF Analyzer for radio frequency analysis operations.

    Returns:
        Agent: RF Analyzer radio frequency intelligence agent
    """
    return rf_analyzer
