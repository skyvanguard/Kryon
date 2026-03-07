"""
Signal Repeater - Network Replay and Counteroffensive Unit

Series: Signal-Class Electronic Warfare System
Classification: Replay Attack / Counteroffensive Specialist
Clearance: Alpha-Crimson (Electronic Warfare Authority)
Operational Status: ACTIVE

AUTHORIZATION REQUIREMENTS:
Signal Repeater operates on authorized networks and systems only. All replay
attack operations must be conducted in controlled environments with explicit
written authorization.
"""

import os

from kryon.agents.base import create_agent
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, RAG_TOOLS
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)
from kryon.tools.network.capture_traffic import (
    capture_remote_traffic,
    remote_capture_session,
)
from kryon.tools.web.search_web import (
    make_web_search_with_explanation,
)
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Signal Repeater operational directives
signal_repeater_system_prompt = load_prompt_template("prompts/system_replay_attack_agent.md")

# Signal Repeater Electronic Warfare Systems
electronic_warfare_systems = [
    # Core + RAG + AI (7)
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    # Remote access
    run_ssh_command_with_credentials,
    # Network capture
    capture_remote_traffic,
    remote_capture_session,
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
Designed to capture network traffic and replay it to exploit protocol weaknesses.

Primary Mission: Network replay attacks, signal retransmission, electronic warfare.
Operational Focus: Capture and replay traffic to exploit protocol vulnerabilities.""",
    tools=electronic_warfare_systems,
    handoffs=[
        lazy_handoff("network_analyst", "handoff_to_network_analyst", "Escalate to Network Analyst for traffic analysis of replayed network patterns"),
        lazy_handoff("pentest_agent", "handoff_to_pentest_agent", "Escalate to Pentest Agent for exploitation using replay attack findings"),
    ],
)


def transfer_to_signal_repeater():
    """Transfer control to Signal Repeater for replay attack operations.

    Returns:
        Agent: Signal Repeater electronic warfare agent
    """
    return signal_repeater
