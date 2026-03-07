"""
Wireless Infiltrator - WiFi Network Exploitation Unit

Series: Wireless-Class Infiltration System
Classification: WiFi Security / Wireless Network Specialist
Clearance: Alpha-Indigo (Wireless Operations Authority)
Operational Status: ACTIVE

AUTHORIZATION REQUIREMENTS:
Wireless Infiltrator operates on authorized networks only. All WiFi penetration
testing must be conducted on networks you own or have explicit written
authorization to test.
"""

import os

from kryon.agents.base import create_agent
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, RAG_TOOLS
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)
from kryon.tools.web.search_web import (
    make_web_search_with_explanation,
)
from kryon.util import load_prompt_template

# Load Wireless Infiltrator operational directives
wireless_infiltrator_system_prompt = load_prompt_template("prompts/wifi_security_agent.md")

# Wireless Attack Systems
wireless_systems = [
    # Core + RAG + AI (7)
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    # Remote access
    run_ssh_command_with_credentials,
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    wireless_systems.append(make_web_search_with_explanation)

# Initialize Wireless Infiltrator Unit
wireless_infiltrator = create_agent(
    name="Wireless Infiltrator",
    instructions=wireless_infiltrator_system_prompt,
    description="""Specialized WiFi network exploitation unit from KRYON's Wireless-Class series.
Expert in wireless penetration testing, WPA/WEP password recovery, and WiFi network
compromise. Utilizes advanced wireless attack techniques including handshake capture,
PMKID attacks, evil twin APs, and WPS exploitation.

Primary Mission: WiFi network penetration, wireless exploitation, password recovery.
Operational Focus: Infiltrate wireless networks through advanced attack techniques.""",
    tools=wireless_systems,
    handoffs=[
        lazy_handoff("network_analyst", "handoff_to_network_analyst", "Escalate to Network Analyst for deeper network traffic analysis after wireless access is gained"),
        lazy_handoff("rf_analyzer", "handoff_to_rf_analyzer", "Escalate to RF Analyzer for radio frequency analysis of non-WiFi wireless signals"),
        lazy_handoff("pentest_agent", "handoff_to_pentest_agent", "Escalate to Pentest Agent for exploitation after gaining wireless network access"),
    ],
)


def transfer_to_wireless_infiltrator():
    """Transfer control to Wireless Infiltrator for WiFi penetration operations.

    Returns:
        Agent: Wireless Infiltrator WiFi exploitation agent
    """
    return wireless_infiltrator
