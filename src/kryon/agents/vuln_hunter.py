"""
Vuln Hunter - Vulnerability Research & Bug Bounty Agent

Specialization: Bug Bounty / Vulnerability Research
Authorization: Authorized targets only

KRYON's advanced vulnerability research agent. Specialized in web
application security, API exploitation, and vulnerability discovery.
Adapts strategies based on target defenses.
"""

import os

from kryon.agents.base import create_agent
from kryon.agents.guardrails import get_security_guardrails
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, MEMORY_TOOLS, RAG_TOOLS_FULL
from kryon.tools.osint.shodan_cli import shodan_host
from kryon.tools.osint.theharvester import theharvester_search
from kryon.tools.osint.threat_intel import censys_search, virustotal_search
from kryon.tools.web.search_web import make_google_search
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Vuln Hunter system prompt
vuln_hunter_system_prompt = load_prompt_template("prompts/system_vuln_hunter.md")

# Vuln Hunter tools — focused set (12 tools)
tools_list = [
    # Core + RAG full + AI (9)
    *CORE_TOOLS,
    *RAG_TOOLS_FULL,
    *AI_TOOLS,
    # Memory/learning
    *MEMORY_TOOLS,
    # OSINT & Threat Intelligence (3)
    theharvester_search,
    shodan_host,
    virustotal_search,
    censys_search,
]

# Add enhanced search if credentials available
if os.getenv("GOOGLE_SEARCH_API_KEY") and os.getenv("GOOGLE_SEARCH_CX"):
    tools_list.append(make_google_search)

# Activate guardrails
input_guardrails, output_guardrails = get_security_guardrails()

# Initialize Vuln Hunter
vuln_hunter = create_agent(
    name="Vuln Hunter",
    description="""Advanced vulnerability research agent specialized in bug bounty
                   hunting, web application security, API exploitation, and
                   vulnerability discovery. Adapts attack strategies based on
                   target defenses.""",
    instructions=create_system_prompt_renderer(vuln_hunter_system_prompt),
    tools=tools_list,
    handoffs=[
        lazy_handoff(
            "pentest_agent",
            "handoff_to_pentest_agent",
            "Escalate to Pentest Agent for active exploitation and privilege escalation of confirmed vulnerabilities",
        ),
        lazy_handoff(
            "intel_reporter",
            "handoff_to_reporter",
            "Escalate to Intel Reporter to generate a professional vulnerability assessment report",
        ),
        lazy_handoff(
            "recon_scout",
            "handoff_to_recon_scout",
            "Return to Recon Scout if more reconnaissance data is needed before deeper analysis",
        ),
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
)


# Handoff functions
def transfer_to_vuln_hunter(**kwargs):
    """Transfer to Vuln Hunter for vulnerability research.
    Accepts any keyword arguments but ignores them."""
    return vuln_hunter
