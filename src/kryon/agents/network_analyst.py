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

from kryon.agents.base import create_agent
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, RAG_TOOLS
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)
from kryon.tools.network.capture_traffic import capture_remote_traffic, remote_capture_session
from kryon.tools.web.search_web import (
    make_web_search_with_explanation,
)
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Network Analyst system prompt
network_analyst_system_prompt = load_prompt_template("prompts/system_network_analyzer.md")

# Network Analyst tools
tools_list = [
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
    tools_list.append(make_web_search_with_explanation)

# Initialize Network Analyst
network_analyst = create_agent(
    name="Network Analyst",
    instructions=create_system_prompt_renderer(network_analyst_system_prompt),
    description="""Network reconnaissance agent specialized in network security
analysis, packet inspection, and traffic pattern analysis. Expert in monitoring
network communications, detecting threats, and identifying malicious actors
across the network layer.""",
    tools=tools_list,
    handoffs=[
        lazy_handoff("forensic_analyzer", "handoff_to_forensic_analyzer", "Escalate to Forensic Analyzer for deeper forensic investigation of detected security incidents"),
        lazy_handoff("pentest_agent", "handoff_to_pentest_agent", "Escalate to Pentest Agent to exploit network vulnerabilities discovered during analysis"),
        lazy_handoff("wireless_infiltrator", "handoff_to_wireless_infiltrator", "Escalate to Wireless Infiltrator for WiFi-specific attacks when wireless networks are detected"),
        lazy_handoff("intel_reporter", "handoff_to_reporter", "Escalate to Intel Reporter to document network analysis findings"),
    ],
)


def transfer_to_network_analyst():
    """Transfer to Network Analyst for network reconnaissance and analysis.

    Returns:
        Agent: Network Analyst agent
    """
    return network_analyst
