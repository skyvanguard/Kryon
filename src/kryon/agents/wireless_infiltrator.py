"""
Wireless Infiltrator - WiFi Network Exploitation Unit

Series: Wireless-Class Infiltration System
Classification: WiFi Security / Wireless Network Specialist
Clearance: Alpha-Indigo (Wireless Operations Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Wireless Infiltrator
PRIMARY FUNCTION: WiFi Network Penetration & Wireless Exploitation
SPECIALIZATION: WiFi Attacks, WPA/WEP Cracking, Wireless Reconnaissance
═══════════════════════════════════════════════════════════════════════

AUTHORIZATION REQUIREMENTS:
Wireless Infiltrator operates on authorized networks only. All WiFi penetration
testing must be conducted on networks you own or have explicit written
authorization to test.
"""

import os

from kryon.agents.base import create_agent
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)
from kryon.tools.reconnaissance.exec_code import (
    execute_code,
)
from kryon.tools.reconnaissance.run_command import (
    run_command,
)
from kryon.tools.web.search_web import (
    make_web_search_with_explanation,
)
from kryon.util import load_prompt_template

# Load Wireless Infiltrator operational directives
wireless_infiltrator_system_prompt = load_prompt_template("prompts/wifi_security_agent.md")

# Wireless Attack Systems - Available WiFi exploitation tools
wireless_systems = [
    run_command,  # System operations for wireless tools
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,  # Script execution for wireless automation
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
PMKID attacks, evil twin APs, and WPS exploitation to infiltrate wireless networks
and test security posture.

Primary Mission: WiFi network penetration, wireless exploitation, password recovery.
Operational Focus: Infiltrate wireless networks through advanced attack techniques.""",
    tools=wireless_systems,
)


def transfer_to_wireless_infiltrator():
    """Transfer control to Wireless Infiltrator for WiFi penetration operations.

    Returns:
        Agent: Wireless Infiltrator WiFi exploitation agent
    """
    return wireless_infiltrator
