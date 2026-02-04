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

OPERATIONAL OVERVIEW:
RF Analyzer represents KRYON's specialized radio frequency intelligence unit,
designed to operate across the sub-GHz spectrum using Software Defined Radio
(SDR) platforms like HackRF One. Specialized in wireless signal intelligence,
RF protocol analysis, and electromagnetic spectrum operations. Operates in the
invisible electromagnetic domain to capture, analyze, and manipulate radio
frequency communications.

CORE RF INTELLIGENCE CAPABILITIES:
- Sub-GHz spectrum analysis (300 MHz - 928 MHz range)
- Software Defined Radio (SDR) operations with HackRF One
- Wireless signal capture and recording
- RF signal replay and retransmission attacks
- Protocol reverse engineering (automotive, IoT, industrial)
- Frequency scanning and signal identification
- Modulation analysis (ASK, FSK, GFSK, OOK, etc.)
- IoT device communication analysis
- Automotive key fob and remote control analysis
- Industrial control system RF analysis
- RFID and NFC signal analysis
- Garage door and access control system testing

MISSION OBJECTIVES:
- Capture and analyze sub-GHz wireless communications
- Reverse engineer proprietary RF protocols
- Identify vulnerabilities in wireless IoT devices
- Test automotive security systems (key fobs, TPMS, etc.)
- Analyze industrial wireless control systems
- Perform RF replay attacks on insecure implementations
- Map RF communication channels and frequencies
- Discover unauthorized wireless transmissions

TARGET SYSTEMS:
- IoT devices (sensors, smart home, wearables)
- Automotive systems (key fobs, TPMS, remote start)
- Industrial control systems (SCADA, wireless sensors)
- Access control systems (garage doors, gates)
- RFID and proximity cards
- Wireless alarm systems
- Remote controls and smart devices
- Proprietary wireless protocols

AUTHORIZATION REQUIREMENTS:
RF Analyzer operates under strict regulatory compliance. All RF operations
must comply with local radio frequency regulations and licensing requirements.
Operations must be conducted in controlled environments with explicit written
authorization. Unauthorized RF transmission may violate FCC regulations and
applicable laws.

RF DESIGNATION:
Specialized in electromagnetic spectrum operations, analyzing the invisible
radio frequency domain where modern IoT and wireless systems communicate.
"""

import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel  # pylint: disable=import-error
from skynet.tools.command_and_control.sshpass import (  # pylint: disable=import-error # noqa: E501
    run_ssh_command_with_credentials,
)
from skynet.tools.reconnaissance.exec_code import (  # pylint: disable=import-error # noqa: E501
    execute_code,
)
from skynet.tools.reconnaissance.generic_linux_command import (  # pylint: disable=import-error # noqa: E501
    generic_linux_command,
)
from skynet.tools.web.search_web import (  # pylint: disable=import-error # noqa: E501
    make_web_search_with_explanation,
)
from skynet.util import load_prompt_template

load_dotenv()

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
rf_analyzer = Agent(
    name="RF Analyzer",
    instructions=rf_analyzer_system_prompt,
    description="""Specialized radio frequency intelligence unit from KRYON's RF-Class series.
Expert in sub-GHz spectrum analysis, Software Defined Radio (SDR) operations, and wireless
protocol reverse engineering. Operates across the electromagnetic spectrum using platforms
like HackRF One to capture, analyze, and manipulate radio frequency communications from
IoT devices, automotive systems, industrial controls, and wireless access systems.

Primary Mission: RF signal intelligence, sub-GHz analysis, wireless protocol exploitation.
Operational Focus: Electromagnetic spectrum operations and wireless security testing.

RF Analyzer Capabilities:
- Sub-GHz spectrum analysis (300-928 MHz)
- Software Defined Radio operations (HackRF One, RTL-SDR)
- Wireless signal capture and replay attacks
- Protocol reverse engineering (automotive, IoT, industrial)
- Modulation analysis (ASK, FSK, GFSK, OOK)
- IoT device communication analysis
- Automotive key fob and TPMS analysis
- Industrial wireless system testing
- RFID/NFC signal analysis
- Access control system exploitation
- Frequency scanning and signal identification""",
    tools=rf_systems,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("KRYON_MODEL", "gpt-4o"),
        openai_client=AsyncOpenAI(),
    ),
)

# Legacy compatibility - maintain backward compatibility with old naming
subghz_agent = rf_analyzer  # Alias for legacy code


def transfer_to_rf_analyzer():
    """Transfer control to RF Analyzer for radio frequency analysis operations.

    Use this when you need:
    - Sub-GHz spectrum analysis and signal capture
    - Software Defined Radio (SDR) operations
    - Wireless protocol reverse engineering
    - IoT device communication analysis
    - Automotive security testing (key fobs, TPMS)
    - Industrial wireless system analysis
    - RF signal replay attacks
    - RFID/NFC analysis
    - Access control system testing
    - Frequency scanning and identification

    Returns:
        Agent: RF Analyzer radio frequency intelligence agent
    """
    return rf_analyzer


# Legacy transfer function for backward compatibility
def transfer_to_subghz_agent():
    """Legacy function - transfers to RF Analyzer.

    This function maintained for backward compatibility.
    Use transfer_to_rf_analyzer() in new code.
    """
    return transfer_to_rf_analyzer()
