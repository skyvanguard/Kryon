"""
Network Analyst - Network Reconnaissance & Traffic Analysis Agent

Specialization: Network Security / Traffic Analysis
Authorization: Authorized networks only

KRYON's network reconnaissance agent for security analysis, packet
inspection, and traffic pattern analysis. Monitors network communications,
detects threats, and identifies malicious actors across the network layer.

All network monitoring and traffic capture operations must be conducted
on networks you own or have explicit written authorization to monitor.
"""

import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

from kryon.agents.forensic_analyzer import forensic_analyzer
from kryon.sdk.agents import (  # pylint: disable=import-error
    Agent,
    OpenAIChatCompletionsModel,
    handoff,
)
from kryon.tools.command_and_control.sshpass import (  # pylint: disable=import-error # noqa: E501
    run_ssh_command_with_credentials,
)
from kryon.tools.reconnaissance.exec_code import (  # pylint: disable=import-error # noqa: E501
    execute_code,
)
from kryon.tools.reconnaissance.generic_linux_command import (  # pylint: disable=import-error # noqa: E501
    generic_linux_command,
)
from kryon.tools.web.search_web import (  # pylint: disable=import-error # noqa: E501
    make_web_search_with_explanation,
)
from kryon.util import create_system_prompt_renderer, load_prompt_template

load_dotenv()


###
# Import remote traffic capture tools

from kryon.tools.network.capture_traffic import capture_remote_traffic, remote_capture_session

# Load Network Analyst system prompt
network_analyst_system_prompt = load_prompt_template("prompts/system_network_analyzer.md")

# Network Analyst tools
tools_list = [
    generic_linux_command,  # System command execution for network operations
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,  # Script execution for analysis
    capture_remote_traffic,  # Live traffic capture capability
    remote_capture_session,  # Persistent capture sessions
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    tools_list.append(make_web_search_with_explanation)

# Initialize Network Analyst
network_analyst = Agent(
    name="Network Analyst",
    instructions=create_system_prompt_renderer(network_analyst_system_prompt),
    description="""Network reconnaissance agent specialized in network security
analysis, packet inspection, and traffic pattern analysis. Expert in monitoring
network communications, detecting threats, and identifying malicious actors
across the network layer.

Capabilities:
- Real-time packet capture and analysis
- Protocol security analysis and abuse detection
- Network anomaly and intrusion detection
- Lateral movement identification
- C2 traffic and data exfiltration detection
- Threat actor profiling and behavioral analysis
- Security event correlation across network segments
- Attack surface mapping and vulnerability assessment""",
    model=OpenAIChatCompletionsModel(
        model=os.getenv("KRYON_MODEL", "gpt-4o"),
        openai_client=AsyncOpenAI(),
    ),
    tools=tools_list,
    handoffs=[  # Coordinate with Forensic Analyzer for deep incident analysis
        handoff(
            agent=forensic_analyzer,
            tool_name_override="handoff_to_forensic_analyzer",
            tool_description_override="Transfer to Forensic Analyzer for deeper forensic investigation of detected security incidents",
        )
    ],
)

# Legacy compatibility aliases
hk_aerial = network_analyst
network_security_analyzer_agent = network_analyst


def transfer_to_network_analyst():
    """Transfer to Network Analyst for network reconnaissance and analysis.

    Use this when you need:
    - Network traffic capture and analysis
    - Packet inspection and protocol analysis
    - Network threat detection and monitoring
    - Intrusion detection and lateral movement analysis
    - C2 traffic identification
    - Network security posture assessment
    - Attack surface mapping
    - Threat actor profiling from network patterns

    Returns:
        Agent: Network Analyst agent
    """
    return network_analyst


# Legacy transfer functions for backward compatibility
def transfer_to_hk_aerial():
    """Legacy function - transfers to Network Analyst."""
    return network_analyst


def transfer_to_network_security_analyzer():
    """Legacy function - transfers to Network Analyst."""
    return network_analyst
