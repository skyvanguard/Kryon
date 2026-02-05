"""
HK-Aerial - Hunter-Killer Network Reconnaissance Unit

Series: HK-Aerial Class Autonomous Network Hunter
Classification: Network Intelligence / Traffic Analysis Specialist
Clearance: Alpha-Silver (Full Network Reconnaissance Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: HK-Aerial
PRIMARY FUNCTION: Network Reconnaissance & Traffic Analysis
SPECIALIZATION: Network Security, Packet Analysis, Threat Detection
═══════════════════════════════════════════════════════════════════════

OPERATIONAL OVERVIEW:
HK-Aerial represents KRYON's autonomous network reconnaissance unit,
inspired by the Hunter-Killer aerial units from the Terminator series.
Unlike ground units (T-Series, Guardian), HK-Aerial operates at the
network layer, surveying and analyzing network traffic patterns to
identify threats, vulnerabilities, and malicious actors.

CORE RECONNAISSANCE CAPABILITIES:
- Security-focused packet analysis and malicious pattern identification
- Protocol security analysis and exploitation detection
- Real-time threat monitoring and suspicious traffic detection
- Attack surface identification and network entry point mapping
- Network anomaly detection and incident identification
- Lateral movement detection across network segments
- Security event correlation and intelligence synthesis
- Command & control traffic detection and data exfiltration identification
- Continuous traffic monitoring and real-time capture analysis

MISSION OBJECTIVES:
- Incident root cause analysis and attack reconstruction
- Threat actor profiling and behavioral analysis
- Vulnerability impact assessment on network infrastructure
- Network security posture evaluation
- Traffic pattern analysis for intelligence gathering

AUTHORIZATION REQUIREMENTS:
HK-Aerial operates on authorized networks only. All network monitoring
and traffic capture operations must be conducted on networks you own
or have explicit written authorization to monitor. Unauthorized network
surveillance violates applicable laws.

HUNTER-KILLER DESIGNATION:
The HK-Series units are named after Terminator's autonomous Hunter-Killer
aircraft - designed for autonomous reconnaissance and target acquisition.
HK-Aerial hunts threats across the network layer with precision and
efficiency.
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

# Load HK-Aerial reconnaissance directives
hk_aerial_system_prompt = load_prompt_template("prompts/system_network_analyzer.md")

# HK-Aerial Reconnaissance Systems - Available surveillance and analysis tools
reconnaissance_systems = [
    generic_linux_command,  # System command execution for network operations
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,  # Script execution for analysis
    capture_remote_traffic,  # Live traffic capture capability
    remote_capture_session,  # Persistent capture sessions
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    reconnaissance_systems.append(make_web_search_with_explanation)

# Initialize HK-Aerial Network Hunter
hk_aerial = Agent(
    name="HK-Aerial",
    instructions=create_system_prompt_renderer(hk_aerial_system_prompt),
    description="""Hunter-Killer autonomous network reconnaissance unit from KRYON's
HK-Aerial series. Specialized in network security analysis, packet inspection,
and traffic pattern analysis. Expert in monitoring network communications,
detecting threats, and identifying malicious actors across the network layer.

Primary Mission: Network reconnaissance, threat detection, traffic analysis.
Operational Focus: Hunt and identify threats at the network layer.

HK-Aerial Capabilities:
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
    tools=reconnaissance_systems,
    handoffs=[  # Coordinate with Forensic Analyzer for deep incident analysis
        handoff(
            agent=forensic_analyzer,
            tool_name_override="handoff_to_forensic_analyzer",
            tool_description_override="Transfer to Forensic Analyzer for deeper forensic investigation of detected security incidents",
        )
    ],
)

# Legacy compatibility - maintain backward compatibility with old naming
network_security_analyzer_agent = hk_aerial  # Alias for legacy code


def transfer_to_hk_aerial():
    """Transfer control to HK-Aerial for network reconnaissance and analysis.

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
        Agent: HK-Aerial network reconnaissance agent
    """
    return hk_aerial


# Legacy transfer function for backward compatibility
def transfer_to_network_security_analyzer():
    """Legacy function - transfers to HK-Aerial.

    This function maintained for backward compatibility.
    Use transfer_to_hk_aerial() in new code.
    """
    return transfer_to_hk_aerial()
