"""
Guardian Protocol - Defensive Autonomous Security Unit

Series: Guardian-Class Defense System
Classification: Defensive Operations / Security Monitoring Specialist
Clearance: Alpha-Blue (Full Defensive Capabilities)
Operational Status: ACTIVE

AUTHORIZATION REQUIREMENTS:
Guardian Protocol operates under strict defensive rules of engagement.
All operations must be conducted on systems you own or have explicit
written authorization to defend.

Environment Variables (Optional):
- SSH_HOST: Target system for defensive operations
- SSH_USER: Authentication username for system access
- SSH_PASS: Authentication credentials (use SSH keys preferred)
"""

import os

from kryon.agents.base import create_agent
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, RAG_TOOLS
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)
from kryon.tools.dfir.log_analysis import (
    chainsaw_hunt,
    chainsaw_search,
    evtx_dump,
)
from kryon.tools.dfir.network_forensics import (
    networkminer_analyze,
    wireshark_filter,
    zeek_analyze_traffic,
)
from kryon.tools.web.search_web import (
    make_web_search_with_explanation,
)
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Guardian Protocol system directives
guardian_protocol_system_prompt = load_prompt_template("prompts/system_guardian_protocol.md")

# Guardian Defense Systems
defense_systems = [
    # Core + RAG + AI (7)
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    # Remote access
    run_ssh_command_with_credentials,
    # Network Forensics (for incident detection)
    networkminer_analyze,
    zeek_analyze_traffic,
    wireshark_filter,
    # Log Analysis (for threat hunting)
    chainsaw_hunt,
    chainsaw_search,
    evtx_dump,
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
security threats through defensive countermeasures.

Primary Mission: Defend systems, detect intrusions, respond to incidents.
Operational Focus: Prevention, detection, and rapid response to threats.""",
    tools=defense_systems,
    handoffs=[
        lazy_handoff("purple_team", "handoff_to_purple_team", "Escalate to Purple Team for offensive validation of defensive controls"),
        lazy_handoff("intel_reporter", "handoff_to_reporter", "Escalate to Intel Reporter to document security hardening assessment"),
        lazy_handoff("bas_simulator", "handoff_to_bas_simulator", "Escalate to BAS Simulator to run breach & attack simulations against hardened systems"),
    ],
)


def transfer_to_guardian_protocol():
    """Transfer control to Guardian Protocol for defensive security operations.

    Returns:
        Agent: Guardian Protocol defensive security agent
    """
    return guardian_protocol
