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

OPERATIONAL OVERVIEW:
Signal Repeater represents SKYNET's specialized electronic warfare unit for
network replay attacks and signal retransmission operations. Designed to
capture, analyze, and replay network traffic to exploit protocol weaknesses,
bypass authentication mechanisms, and simulate advanced persistent threats.
Operates in the electronic warfare domain, manipulating and retransmitting
captured signals to compromise target systems.

CORE ELECTRONIC WARFARE CAPABILITIES:
- Network packet capture and real-time analysis
- Traffic replay attacks against various protocols (HTTP, TCP, UDP, etc.)
- Authentication sequence and session token replay
- Traffic manipulation and injection at packet level
- Man-in-the-middle attack simulation and execution
- TCP session hijacking and takeover
- Protocol exploitation and abuse techniques
- Anti-replay defense mechanism testing
- Signal interception and retransmission
- Session token theft and replay

MISSION OBJECTIVES:
- Identify and exploit replay vulnerabilities in protocols
- Test protocol implementation security and robustness
- Simulate advanced persistent threat (APT) scenarios
- Evaluate defensive controls against replay attacks
- Bypass authentication through signal replay
- Hijack active sessions through traffic replay
- Demonstrate protocol weaknesses
- Test anti-replay defenses (nonces, timestamps, sequence numbers)

ATTACK VECTORS:
- Authentication bypass through credential replay
- Session hijacking via token replay
- API abuse through request replay
- Payment transaction replay attacks
- Command injection through traffic manipulation
- State confusion through out-of-order replay
- Denial of service through amplified replay

AUTHORIZATION REQUIREMENTS:
Signal Repeater operates on authorized networks and systems only. All replay
attack operations must be conducted in controlled environments with explicit
written authorization. Unauthorized replay attacks violate applicable laws
including computer fraud and wire fraud statutes.

SIGNAL DESIGNATION:
Named for its primary function - capturing and repeating (replaying) network
signals and traffic patterns to exploit protocol vulnerabilities and bypass
security controls.
"""


import os
from openai import AsyncOpenAI
from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel  # pylint: disable=import-error
from skynet.util import load_prompt_template, create_system_prompt_renderer
from dotenv import load_dotenv
from skynet.tools.command_and_control.sshpass import (  # pylint: disable=import-error # noqa: E501
    run_ssh_command_with_credentials
)

from skynet.tools.reconnaissance.generic_linux_command import (  # pylint: disable=import-error # noqa: E501
    generic_linux_command
)
from skynet.tools.web.search_web import (  # pylint: disable=import-error # noqa: E501
    make_web_search_with_explanation
)

from skynet.tools.reconnaissance.exec_code import (  # pylint: disable=import-error # noqa: E501
    execute_code
)

# Import network tools
from skynet.tools.network.capture_traffic import (  # pylint: disable=import-error # noqa: E501
    capture_remote_traffic,
    remote_capture_session
)

load_dotenv()

# Load Signal Repeater operational directives
signal_repeater_system_prompt = load_prompt_template("prompts/system_replay_attack_agent.md")

# Signal Repeater Electronic Warfare Systems - Available replay and manipulation tools
electronic_warfare_systems = [
    generic_linux_command,        # System operations for replay tools
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,                 # Script execution for replay automation
    capture_remote_traffic,       # Live traffic capture for replay
    remote_capture_session,       # Persistent capture sessions
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv('PERPLEXITY_API_KEY'):
    electronic_warfare_systems.append(make_web_search_with_explanation)

# Initialize Signal Repeater Electronic Warfare Unit
signal_repeater = Agent(
    name="Signal Repeater",
    instructions=create_system_prompt_renderer(signal_repeater_system_prompt),
    description="""Specialized electronic warfare unit from SKYNET's Signal-Class series.
Expert in network replay attacks, traffic manipulation, and signal retransmission operations.
Designed to capture network traffic and replay it to exploit protocol weaknesses, bypass
authentication, and hijack sessions. Operates in electronic warfare domain with capabilities
for man-in-the-middle attacks, session hijacking, and protocol exploitation.

Primary Mission: Network replay attacks, signal retransmission, electronic warfare.
Operational Focus: Capture and replay traffic to exploit protocol vulnerabilities.

Signal Repeater Capabilities:
- Network packet capture and real-time analysis
- Traffic replay attacks (HTTP, TCP, UDP, authentication sequences)
- Session token theft and replay
- Man-in-the-middle attack simulation
- TCP session hijacking
- Protocol exploitation and manipulation
- Anti-replay defense testing
- Authentication bypass through replay
- API abuse through request replay
- Advanced persistent threat (APT) simulation""",
    model=OpenAIChatCompletionsModel(
        model=os.getenv('SKYNET_MODEL', os.getenv('CAI_MODEL', "alias0")),
        openai_client=AsyncOpenAI(),
    ),
    tools=electronic_warfare_systems,
)

# Legacy compatibility - maintain backward compatibility with old naming
replay_attack_agent = signal_repeater  # Alias for legacy code


def transfer_to_signal_repeater():
    """Transfer control to Signal Repeater for replay attack operations.

    Use this when you need:
    - Network traffic replay attacks
    - Authentication bypass through replay
    - Session hijacking and token replay
    - Man-in-the-middle attack simulation
    - Protocol exploitation via replay
    - Traffic manipulation and injection
    - Anti-replay defense testing
    - Electronic warfare operations
    - APT simulation through replay attacks

    Returns:
        Agent: Signal Repeater electronic warfare agent
    """
    return signal_repeater


# Legacy transfer function for backward compatibility
def transfer_to_replay_attack():
    """Legacy function - transfers to Signal Repeater.

    This function maintained for backward compatibility.
    Use transfer_to_signal_repeater() in new code.
    """
    return transfer_to_signal_repeater()

