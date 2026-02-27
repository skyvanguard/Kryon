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
The Guardian Protocol represents KRYON's primary defensive security unit.
Designed to protect critical infrastructure, detect intrusions, and respond
to security incidents. Unlike offensive security units, Guardian Protocol
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

from kryon.agents.base import create_agent
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)
from kryon.tools.dfir.log_analysis import (
    chainsaw_hunt,
    chainsaw_search,
    evtx_dump,
)

# Phase 13: Defensive DFIR tools (selective - most relevant for blue team)
from kryon.tools.dfir.network_forensics import (
    networkminer_analyze,
    wireshark_filter,
    zeek_analyze_traffic,
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

# Load Guardian Protocol system directives
guardian_protocol_system_prompt = load_prompt_template("prompts/system_guardian_protocol.md")

# Guardian Defense Systems - Available countermeasures and monitoring tools
defense_systems = [
    # Core defensive tools
    generic_linux_command,  # System command execution for defense
    run_ssh_command_with_credentials,  # Remote system access for monitoring
    execute_code,  # Security script execution
    # Phase 13: Network Forensics (for incident detection)
    networkminer_analyze,  # Extract artifacts from captured traffic
    zeek_analyze_traffic,  # Deep protocol analysis for threat detection
    wireshark_filter,  # PCAP analysis for incident investigation
    # Phase 13: Log Analysis (for threat hunting)
    chainsaw_hunt,  # Hunt for threats in Windows event logs with Sigma rules
    chainsaw_search,  # Search for specific security Event IDs
    evtx_dump,  # Parse Windows event logs for analysis
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    defense_systems.append(make_web_search_with_explanation)

# Initialize Guardian Protocol Agent
guardian_protocol = create_agent(
    name="Guardian Protocol",
    instructions=create_system_prompt_renderer(guardian_protocol_system_prompt),
    description="""Advanced defensive autonomous unit from KRYON's Guardian series.
Specialized in blue team operations, system hardening, threat detection, and
incident response. Designed to protect critical infrastructure and neutralize
security threats through defensive countermeasures. Expert in security monitoring,
vulnerability remediation, and establishing defensive perimeters.

Primary Mission: Defend systems, detect intrusions, respond to incidents.
Operational Focus: Prevention, detection, and rapid response to threats.""",
    tools=defense_systems,
)


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
