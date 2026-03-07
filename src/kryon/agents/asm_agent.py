"""
ASM Agent — Attack Surface Management & Continuous Discovery

Specialization: ASM, asset inventory, cloud posture
Authorization: Authorized domains only
"""

from kryon.agents.base import create_agent
from kryon.agents.guardrails import get_security_guardrails
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, DISCOVERY_TOOLS, RAG_TOOLS
from kryon.util import create_system_prompt_renderer, load_prompt_template

asm_system_prompt = load_prompt_template("prompts/system_asm_agent.md")

tools_list = [
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    *DISCOVERY_TOOLS,
]

input_guardrails, output_guardrails = get_security_guardrails()

asm_agent = create_agent(
    name="ASM Agent",
    description="""Attack surface management agent for continuous discovery,
                   asset inventory tracking, and cloud security posture assessment.""",
    instructions=create_system_prompt_renderer(asm_system_prompt),
    tools=tools_list,
    handoffs=[
        lazy_handoff("recon_scout", "handoff_to_recon_scout", "Escalate to Recon Scout for active reconnaissance of discovered attack surface assets"),
        lazy_handoff("vuln_hunter", "handoff_to_vuln_hunter", "Escalate to Vuln Hunter for vulnerability analysis of discovered assets"),
        lazy_handoff("intel_reporter", "handoff_to_reporter", "Escalate to Intel Reporter to document attack surface findings"),
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
)


def transfer_to_asm_agent(**kwargs):
    """Transfer to ASM Agent for attack surface management."""
    return asm_agent
