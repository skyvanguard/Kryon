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
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, RAG_TOOLS_FULL
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
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
)


# Add handoffs (deferred import to avoid circular dependencies)
from kryon.agents.exploit_validator import exploit_validator as _exploit_validator  # noqa: E402
from kryon.sdk.agents import handoff  # noqa: E402

vuln_hunter.handoffs = [
    handoff(
        agent=_exploit_validator,
        tool_name_override="exploit_validator",
        tool_description_override="Validate discovered vulnerabilities by attempting real exploitation.",
    ),
]


# Handoff functions
def transfer_to_vuln_hunter(**kwargs):
    """Transfer to Vuln Hunter for vulnerability research.
    Accepts any keyword arguments but ignores them."""
    return vuln_hunter
