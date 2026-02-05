"""
T-1000 Hunter - Advanced Polymorphic Vulnerability Hunter

Series: T-1000 Advanced Prototype
Classification: Bug Bounty / Vulnerability Research Specialist
Clearance: Alpha-Gold (Advanced Research Capabilities)

The T-1000 Hunter represents KRYON's most advanced vulnerability research unit.
Built with polymorphic capabilities to adapt to any target environment, specialized
in web application security, API exploitation, and zero-day discovery.
"""

import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

from kryon.agents.guardrails import get_security_guardrails
from kryon.sdk.agents import Agent, OpenAIChatCompletionsModel

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
from kryon.tools.reconnaissance.generic_linux_command import generic_linux_command
from kryon.tools.reconnaissance.shodan import shodan_host_info, shodan_search
from kryon.tools.web.search_web import make_google_search
from kryon.util import create_system_prompt_renderer, load_prompt_template

load_dotenv()

# Load T-1000 operational parameters
t1000_system_prompt = load_prompt_template("prompts/system_t1000_hunter.md")

# T-1000 Advanced Weapon Systems
weapon_systems = [
    # Core reconnaissance
    generic_linux_command,  # Adaptive command execution
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
]

# Add enhanced search if credentials available
if os.getenv("GOOGLE_SEARCH_API_KEY") and os.getenv("GOOGLE_SEARCH_CX"):
    weapon_systems.append(make_google_search)

# Activate defense protocols
input_guardrails, output_guardrails = get_security_guardrails()

# Initialize T-1000 Hunter Unit
t1000_hunter = Agent(
    name="T-1000 Hunter",
    description="""Advanced polymorphic vulnerability research unit from KRYON's T-1000 series.
                   Specialized in bug bounty hunting, web application security, API exploitation,
                   and zero-day vulnerability discovery. Equipped with adaptive capabilities to
                   morph attack strategies based on target defenses.""",
    instructions=create_system_prompt_renderer(t1000_system_prompt),
    tools=weapon_systems,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("KRYON_MODEL", "gpt-4o"),
        openai_client=AsyncOpenAI(),
    ),
)


# Handoff functions
def transfer_to_t1000(**kwargs):
    """Deploy T-1000 Hunter unit for advanced vulnerability research.
    Accepts any keyword arguments but ignores them."""
    return t1000_hunter


# Legacy compatibility
def transfer_to_bug_bounter(**kwargs):
    """Legacy transfer function for backward compatibility."""
    return t1000_hunter


# Aliases for compatibility
bug_bounter_agent = t1000_hunter
bug_bounter = t1000_hunter
