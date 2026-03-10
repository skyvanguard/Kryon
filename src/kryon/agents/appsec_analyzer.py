"""
AppSec Analyzer — Application Security Pipeline Agent

Specialization: SAST/DAST/SCA/API Security/Supply Chain
Authorization: Authorized code repositories and applications only
"""

from kryon.agents.base import create_agent
from kryon.agents.guardrails import get_security_guardrails
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, APPSEC_TOOLS, CORE_TOOLS, MEMORY_TOOLS, RAG_TOOLS
from kryon.util import create_system_prompt_renderer, load_prompt_template

appsec_system_prompt = load_prompt_template("prompts/system_appsec_analyzer.md")

tools_list = [
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    *APPSEC_TOOLS,
    *MEMORY_TOOLS,  # Memory/learning
]

input_guardrails, output_guardrails = get_security_guardrails()

appsec_analyzer = create_agent(
    name="AppSec Analyzer",
    description="""Application security pipeline agent for SAST, DAST, SCA,
                   API security testing, and supply chain analysis. Orchestrates
                   Semgrep, ZAP, Syft/Grype, and custom API security checks.""",
    instructions=create_system_prompt_renderer(appsec_system_prompt),
    tools=tools_list,
    handoffs=[
        lazy_handoff(
            "vuln_hunter",
            "handoff_to_vuln_hunter",
            "Escalate to Vuln Hunter for deep vulnerability analysis of application security findings",
        ),
        lazy_handoff(
            "api_fuzzer",
            "handoff_to_api_fuzzer",
            "Escalate to API Fuzzer for API-specific security testing when API endpoints are found",
        ),
        lazy_handoff(
            "chrome_infiltrator",
            "handoff_to_chrome_infiltrator",
            "Escalate to Chrome Infiltrator for browser-based testing of XSS and DOM vulnerabilities",
        ),
        lazy_handoff(
            "intel_reporter",
            "handoff_to_reporter",
            "Escalate to Intel Reporter to document application security assessment findings",
        ),
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
)


def transfer_to_appsec_analyzer(**kwargs):
    """Transfer to AppSec Analyzer for application security assessment."""
    return appsec_analyzer
