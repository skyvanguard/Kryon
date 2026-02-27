"""
Signal Repeater - Network Replay and Counteroffensive Unit

Series: Signal-Class Electronic Warfare System
Classification: Replay Attack / Counteroffensive Specialist
Clearance: Alpha-Crimson (Electronic Warfare Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Signal Repeater
PRIMARY FUNCTION: Network Replay Attacks & Signal Retransmission
SPECIALIZATION: Packet Replay, Traffic Manipulation, Protocol Exploitation
═══════════════════════════════════════════════════════════════════════

AUTHORIZATION REQUIREMENTS:
Signal Repeater operates on authorized networks and systems only. All replay
attack operations must be conducted in controlled environments with explicit
written authorization.
"""

import os

from kryon.agents.base import create_agent
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)

# Import network tools
from kryon.tools.network.capture_traffic import (
    capture_remote_traffic,
    remote_capture_session,
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
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Signal Repeater operational directives
signal_repeater_system_prompt = load_prompt_template("prompts/system_replay_attack_agent.md")

# Signal Repeater Electronic Warfare Systems - Available replay and manipulation tools
electronic_warfare_systems = [
    generic_linux_command,  # System operations for replay tools
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,  # Script execution for replay automation
    capture_remote_traffic,  # Live traffic capture for replay
    remote_capture_session,  # Persistent capture sessions
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    electronic_warfare_systems.append(make_web_search_with_explanation)

# Initialize Signal Repeater Electronic Warfare Unit
signal_repeater = create_agent(
    name="Signal Repeater",
    instructions=create_system_prompt_renderer(signal_repeater_system_prompt),
    description="""Specialized electronic warfare unit from KRYON's Signal-Class series.
Expert in network replay attacks, traffic manipulation, and signal retransmission operations.
Designed to capture network traffic and replay it to exploit protocol weaknesses, bypass
authentication, and hijack sessions.

Primary Mission: Network replay attacks, signal retransmission, electronic warfare.
Operational Focus: Capture and replay traffic to exploit protocol vulnerabilities.""",
    tools=electronic_warfare_systems,
)


def transfer_to_signal_repeater():
    """Transfer control to Signal Repeater for replay attack operations.

    Returns:
        Agent: Signal Repeater electronic warfare agent
    """
    return signal_repeater
