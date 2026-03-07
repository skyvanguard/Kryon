"""
Purple Team — Offensive Validation & Detection Engineering Agent

Specialization: BAS, Detection as Code, MITRE ATT&CK Coverage
Authorization: Authorized environments only
"""

from kryon.agents.base import create_agent
from kryon.agents.guardrails import get_security_guardrails
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, RAG_TOOLS, VALIDATION_TOOLS
from kryon.util import create_system_prompt_renderer, load_prompt_template

purple_team_system_prompt = load_prompt_template("prompts/system_purple_team.md")

tools_list = [
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    *VALIDATION_TOOLS,
]

input_guardrails, output_guardrails = get_security_guardrails()

purple_team = create_agent(
    name="Purple Team",
    description="""Offensive validation agent for breach & attack simulation,
                   detection validation, and MITRE ATT&CK coverage scoring.
                   Generates Sigma, YARA, and Suricata detection rules.""",
    instructions=create_system_prompt_renderer(purple_team_system_prompt),
    tools=tools_list,
    handoffs=[
        lazy_handoff("guardian_protocol", "handoff_to_guardian_protocol", "Escalate to Guardian Protocol for defensive hardening based on attack simulation results"),
        lazy_handoff("bas_simulator", "handoff_to_bas_simulator", "Escalate to BAS Simulator for automated MITRE ATT&CK scenario execution"),
        lazy_handoff("intel_reporter", "handoff_to_reporter", "Escalate to Intel Reporter to document purple team exercise findings"),
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
)


def transfer_to_purple_team(**kwargs):
    """Transfer to Purple Team for offensive validation."""
    return purple_team
