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
from kryon.tools.ai.claude_code import claude_code

# Phase 22: RAG Knowledge Base Integration
from kryon.tools.knowledge import (
    get_exploit_techniques,
    get_knowledge_stats,
    get_security_tools,
    query_knowledge_base,
    search_vulnerabilities,
)
from kryon.tools.osint.shodan_cli import shodan_host

# Phase 12: OSINT & Threat Intelligence tools
from kryon.tools.osint.theharvester import theharvester_search
from kryon.tools.osint.threat_intel import censys_search, recon_ng_search, virustotal_search
from kryon.tools.osint.yara_scan import yara_scan_directory, yara_scan_file
from kryon.tools.reconnaissance.exec_code import execute_code
from kryon.tools.reconnaissance.run_command import run_command
from kryon.tools.reconnaissance.shodan import shodan_host_info, shodan_search
from kryon.tools.web.search_web import make_google_search
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Vuln Hunter system prompt
vuln_hunter_system_prompt = load_prompt_template("prompts/system_vuln_hunter.md")

# Vuln Hunter tools
tools_list = [
    # Core reconnaissance
    run_command,  # Adaptive command execution
    execute_code,  # Code analysis and execution
    # Internet-wide intelligence (Shodan - legacy)
    shodan_search,  # Global intelligence gathering
    shodan_host_info,  # Target reconnaissance
    # Phase 12: OSINT & Threat Intelligence
    theharvester_search,  # Email/subdomain/host harvesting from public sources
    shodan_host,  # Detailed host information (Phase 12 version)
    virustotal_search,  # Threat intelligence and reputation lookup
    censys_search,  # Certificate and host intelligence
    recon_ng_search,  # Advanced modular reconnaissance
    yara_scan_file,  # Malware pattern detection (single file)
    yara_scan_directory,  # Malware pattern detection (directory scan)
    # Phase 22: RAG Knowledge Base Access
    query_knowledge_base,  # Query KRYON knowledge base (103 CVEs + security tools)
    search_vulnerabilities,  # Search for specific CVEs by technology/version
    get_exploit_techniques,  # Get exploitation techniques for attack types
    get_security_tools,  # Find security tools from GitHub knowledge
    get_knowledge_stats,  # Get knowledge base statistics
    # AI Delegation — complex tasks to Claude Code CLI
    claude_code,
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


# Handoff functions
def transfer_to_vuln_hunter(**kwargs):
    """Transfer to Vuln Hunter for vulnerability research.
    Accepts any keyword arguments but ignores them."""
    return vuln_hunter
