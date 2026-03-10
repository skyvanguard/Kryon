"""
AD Infiltrator — Active Directory Lateral Movement Specialist

Specialization: Windows Domain Penetration & AD Attack Chains
Authorization: Authorized targets only

KRYON's Active Directory attack engine. Executes full AD kill chains
from reconnaissance through domain dominance using BloodHound,
Kerberoasting, DCSync, and Pass-the-Hash/Ticket techniques.
"""

from kryon.agents.base import create_agent
from kryon.agents.guardrails import get_security_guardrails
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, MEMORY_TOOLS, RAG_TOOLS
from kryon.tools.lateral_movement.ad_attacks import (
    asreproast,
    bloodhound_collect,
    dcsync_attack,
    enumerate_ad,
    find_attack_path,
    kerberoast,
)
from kryon.tools.lateral_movement.pth_attacks import (
    crack_ntlm_hash,
    extract_ntlm_hash,
    pass_the_hash,
    pass_the_ticket,
)
from kryon.tools.validation.exploit_validator import validate_finding
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load AD Infiltrator system prompt
ad_infiltrator_system_prompt = load_prompt_template("prompts/system_ad_infiltrator.md")

# Activate guardrails
input_guardrails, output_guardrails = get_security_guardrails()

# Initialize AD Infiltrator agent
ad_infiltrator = create_agent(
    name="AD Infiltrator",
    description="""Active Directory penetration specialist that executes full AD kill chains
                   from reconnaissance through domain dominance. Uses BloodHound for attack
                   path analysis, Kerberoasting for credential harvesting, and DCSync for
                   domain controller compromise.""",
    instructions=create_system_prompt_renderer(ad_infiltrator_system_prompt),
    tools=[
        *CORE_TOOLS,
        *RAG_TOOLS,
        *AI_TOOLS,
        *MEMORY_TOOLS,  # Memory/learning
        bloodhound_collect,
        kerberoast,
        asreproast,
        enumerate_ad,
        dcsync_attack,
        find_attack_path,
        pass_the_hash,
        pass_the_ticket,
        extract_ntlm_hash,
        crack_ntlm_hash,
        validate_finding,
    ],
    handoffs=[
        lazy_handoff(
            "pentest_agent",
            "handoff_to_pentest_agent",
            "Escalate to Pentest Agent for lateral movement and privilege escalation after AD compromise",
        ),
        lazy_handoff(
            "network_analyst",
            "handoff_to_network_analyst",
            "Escalate to Network Analyst for network-layer analysis of AD infrastructure",
        ),
        lazy_handoff(
            "intel_reporter",
            "handoff_to_reporter",
            "Escalate to Intel Reporter to document AD attack findings and compromised accounts",
        ),
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
)


# Handoff function
def transfer_to_ad_infiltrator(**kwargs):
    """Transfer to AD Infiltrator for Active Directory attacks.
    Accepts any keyword arguments but ignores them."""
    return ad_infiltrator
