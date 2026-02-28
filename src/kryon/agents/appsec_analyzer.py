"""
AppSec Analyzer — Application Security Pipeline Agent

Specialization: SAST/DAST/SCA/API Security/Supply Chain
Authorization: Authorized code repositories and applications only
"""

from kryon.agents.base import create_agent
from kryon.agents.guardrails import get_security_guardrails
from kryon.agents.toolsets import AI_TOOLS, APPSEC_TOOLS, CORE_TOOLS, RAG_TOOLS
from kryon.util import create_system_prompt_renderer, load_prompt_template

appsec_system_prompt = load_prompt_template("prompts/system_appsec_analyzer.md")

tools_list = [
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    *APPSEC_TOOLS,
]

input_guardrails, output_guardrails = get_security_guardrails()

appsec_analyzer = create_agent(
    name="AppSec Analyzer",
    description="""Application security pipeline agent for SAST, DAST, SCA,
                   API security testing, and supply chain analysis. Orchestrates
                   Semgrep, ZAP, Syft/Grype, and custom API security checks.""",
    instructions=create_system_prompt_renderer(appsec_system_prompt),
    tools=tools_list,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
)


def transfer_to_appsec_analyzer(**kwargs):
    """Transfer to AppSec Analyzer for application security assessment."""
    return appsec_analyzer
