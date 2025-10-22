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

OPERATIONAL OVERVIEW:
Wireless Infiltrator represents SKYNET's specialized WiFi network exploitation
unit, designed to infiltrate and compromise wireless networks through advanced
penetration techniques. Specialized in WiFi security testing, password recovery,
handshake capture, and wireless network reconnaissance. Operates at the 2.4GHz
and 5GHz bands to identify vulnerabilities in wireless infrastructure and gain
unauthorized access to target networks.

CORE WIRELESS CAPABILITIES:
- WiFi network reconnaissance and scanning
- WPA/WPA2/WPA3 handshake capture
- WEP/WPA password cracking and recovery
- Evil twin and rogue access point attacks
- Wireless deauthentication attacks
- WiFi jamming and denial of service
- PMKID attack for password-less WPA2 cracking
- WiFi Protected Setup (WPS) exploitation
- Hidden SSID discovery
- Client isolation testing
- Wireless packet injection
- WiFi network mapping and visualization

MISSION OBJECTIVES:
- Compromise WiFi network security
- Capture WPA handshakes for offline cracking
- Recover WiFi passwords through various attack vectors
- Deploy evil twin access points for credential harvesting
- Test wireless infrastructure security posture
- Identify weak WiFi security configurations
- Perform wireless penetration testing
- Evaluate defense against wireless attacks

ATTACK VECTORS:
- WPA/WPA2 handshake capture and offline cracking
- PMKID attack for WPA2 without client interaction
- WPS PIN brute force and Pixie Dust attacks
- Evil twin AP for credential phishing
- Deauthentication attacks to force reconnections
- Captive portal bypass techniques
- WiFi jamming for denial of service
- Client-side attacks through wireless MitM

TOOL ARSENAL:
- aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng)
- Wireless adapter with monitor mode and packet injection
- hashcat/john for password cracking
- Reaver/Bully for WPS attacks
- hostapd for rogue AP deployment
- WiFi Pineapple compatible techniques

AUTHORIZATION REQUIREMENTS:
Wireless Infiltrator operates on authorized networks only. All WiFi penetration
testing must be conducted on networks you own or have explicit written
authorization to test. Unauthorized WiFi hacking violates Computer Fraud and
Abuse Act (CFAA) and applicable laws.

WIRELESS DESIGNATION:
Designed for infiltration of wireless networks, exploiting the invisible
electromagnetic waves that connect the modern world.
"""
import os
from dotenv import load_dotenv
from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel  # pylint: disable=import-error
from openai import AsyncOpenAI
from skynet.util import load_prompt_template
from skynet.tools.command_and_control.sshpass import (  # pylint: disable=import-error # noqa: E501
    run_ssh_command_with_credentials
)

from skynet.tools.reconnaissance.generic_linux_command import (  # pylint: disable=import-error # noqa: E501
    generic_linux_command
)
from skynet.tools.web.search_web import (  # pylint: disable=import-error # noqa: E501
    make_web_search_with_explanation,
)

from skynet.tools.reconnaissance.exec_code import (  # pylint: disable=import-error # noqa: E501
    execute_code
)

load_dotenv()

# Load Wireless Infiltrator operational directives
wireless_infiltrator_system_prompt = load_prompt_template("prompts/wifi_security_agent.md")

# Wireless Attack Systems - Available WiFi exploitation tools
wireless_systems = [
    generic_linux_command,        # System operations for wireless tools
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,                 # Script execution for wireless automation
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv('PERPLEXITY_API_KEY'):
    wireless_systems.append(make_web_search_with_explanation)

# Initialize Wireless Infiltrator Unit
wireless_infiltrator = Agent(
    name="Wireless Infiltrator",
    instructions=wireless_infiltrator_system_prompt,
    description="""Specialized WiFi network exploitation unit from SKYNET's Wireless-Class series.
Expert in wireless penetration testing, WPA/WEP password recovery, and WiFi network
compromise. Utilizes advanced wireless attack techniques including handshake capture,
PMKID attacks, evil twin APs, and WPS exploitation to infiltrate wireless networks
and test security posture.

Primary Mission: WiFi network penetration, wireless exploitation, password recovery.
Operational Focus: Infiltrate wireless networks through advanced attack techniques.

Wireless Infiltrator Capabilities:
- WiFi reconnaissance and network scanning
- WPA/WPA2/WPA3 handshake capture
- Password cracking (WEP, WPA, WPA2)
- PMKID attack for password-less compromise
- Evil twin and rogue AP deployment
- Deauthentication attacks
- WPS exploitation (PIN, Pixie Dust)
- Hidden SSID discovery
- WiFi jamming and DoS
- Wireless packet injection
- Using aircrack-ng suite, hashcat, Reaver""",
    tools=wireless_systems,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('SKYNET_MODEL', os.getenv('CAI_MODEL', "alias0")),
        openai_client=AsyncOpenAI(),
    )
)

# Legacy compatibility - maintain backward compatibility with old naming
wifi_security_agent = wireless_infiltrator  # Alias for legacy code


def transfer_to_wireless_infiltrator():
    """Transfer control to Wireless Infiltrator for WiFi penetration operations.

    Use this when you need:
    - WiFi network penetration testing
    - WPA/WPA2/WPA3 password recovery
    - Handshake capture and cracking
    - Evil twin and rogue AP attacks
    - Deauthentication attacks
    - WPS exploitation
    - WiFi reconnaissance and mapping
    - Wireless security assessment
    - WiFi jamming and DoS testing

    Returns:
        Agent: Wireless Infiltrator WiFi exploitation agent
    """
    return wireless_infiltrator


# Legacy transfer function for backward compatibility
def transfer_to_wifi_security():
    """Legacy function - transfers to Wireless Infiltrator.

    This function maintained for backward compatibility.
    Use transfer_to_wireless_infiltrator() in new code.
    """
    return transfer_to_wireless_infiltrator()
