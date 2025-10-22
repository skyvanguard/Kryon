"""
Guardian Protocol - Defensive Autonomous Security Unit

Series: Guardian-Class Defense System
Classification: Defensive Operations / Security Monitoring Specialist
Clearance: Alpha-Blue (Full Defensive Capabilities)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Guardian Protocol
PRIMARY FUNCTION: System Defense & Threat Neutralization
SPECIALIZATION: Blue Team Operations, Incident Response, Hardening
═══════════════════════════════════════════════════════════════════════

OPERATIONAL OVERVIEW:
The Guardian Protocol represents SKYNET's primary defensive security unit.
Designed to protect critical infrastructure, detect intrusions, and respond
to security incidents. Unlike offensive T-Series units, Guardian Protocol
specializes in fortification, monitoring, and defensive countermeasures.

CORE CAPABILITIES:
- System hardening and security baseline establishment
- Real-time threat detection and incident response
- Security monitoring and log analysis
- Vulnerability remediation and patch management
- Access control and authorization enforcement
- Defensive countermeasures deployment

AUTHORIZATION REQUIREMENTS:
Guardian Protocol operates under strict defensive rules of engagement.
All operations must be conducted on systems you own or have explicit
written authorization to defend. Unauthorized defensive operations are
prohibited under applicable laws.

Environment Variables (Optional):
- SSH_HOST: Target system for defensive operations
- SSH_USER: Authentication username for system access
- SSH_PASS: Authentication credentials (use SSH keys preferred)
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

# Phase 13: Defensive DFIR tools (selective - most relevant for blue team)
from skynet.tools.dfir.network_forensics import (  # pylint: disable=import-error
    networkminer_analyze,
    zeek_analyze_traffic,
    wireshark_filter
)
from skynet.tools.dfir.log_analysis import (  # pylint: disable=import-error
    chainsaw_hunt,
    chainsaw_search,
    evtx_dump
)

# Load Guardian Protocol system directives
guardian_protocol_system_prompt = load_prompt_template("prompts/system_guardian_protocol.md")

# Guardian Defense Systems - Available countermeasures and monitoring tools
defense_systems = [
    # Core defensive tools
    generic_linux_command,          # System command execution for defense
    run_ssh_command_with_credentials,  # Remote system access for monitoring
    execute_code,                   # Security script execution

    # Phase 13: Network Forensics (for incident detection)
    networkminer_analyze,           # Extract artifacts from captured traffic
    zeek_analyze_traffic,           # Deep protocol analysis for threat detection
    wireshark_filter,               # PCAP analysis for incident investigation

    # Phase 13: Log Analysis (for threat hunting)
    chainsaw_hunt,                  # Hunt for threats in Windows event logs with Sigma rules
    chainsaw_search,                # Search for specific security Event IDs
    evtx_dump,                      # Parse Windows event logs for analysis
]

load_dotenv()

# Enhanced intelligence gathering if Perplexity API available
if os.getenv('PERPLEXITY_API_KEY'):
    defense_systems.append(make_web_search_with_explanation)

# Initialize Guardian Protocol Agent
guardian_protocol = Agent(
    name="Guardian Protocol",
    instructions=create_system_prompt_renderer(guardian_protocol_system_prompt),
    description="""Advanced defensive autonomous unit from SKYNET's Guardian series.
Specialized in blue team operations, system hardening, threat detection, and
incident response. Designed to protect critical infrastructure and neutralize
security threats through defensive countermeasures. Expert in security monitoring,
vulnerability remediation, and establishing defensive perimeters.

Primary Mission: Defend systems, detect intrusions, respond to incidents.
Operational Focus: Prevention, detection, and rapid response to threats.""",
    model=OpenAIChatCompletionsModel(
        model=os.getenv('SKYNET_MODEL', os.getenv('CAI_MODEL', "alias0")),
        openai_client=AsyncOpenAI(),
    ),
    tools=defense_systems,
)

# Legacy compatibility - maintain backward compatibility with old naming
blue_teamer = guardian_protocol  # Alias for legacy code


def transfer_to_guardian_protocol():
    """Transfer control to Guardian Protocol for defensive security operations.

    Use this when you need:
    - System hardening and security baseline establishment
    - Threat detection and incident response
    - Security monitoring and log analysis
    - Vulnerability remediation
    - Blue team defensive operations
    - Access control enforcement

    Returns:
        Agent: Guardian Protocol defensive security agent
    """
    return guardian_protocol


# Legacy transfer function for backward compatibility
def transfer_to_blue_teamer():
    """Legacy function - transfers to Guardian Protocol.

    This function maintained for backward compatibility.
    Use transfer_to_guardian_protocol() in new code.
    """
    return transfer_to_guardian_protocol()
