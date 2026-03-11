"""
Recon Scout - Basic Reconnaissance & CTF Agent

Specialization: Reconnaissance / CTF Challenges
Authorization: Authorized targets only

KRYON's entry-level autonomous agent for basic reconnaissance operations,
CTF challenges, and initial target assessment. Lightweight and fast
for rapid deployment.
"""

from kryon.agents.base import create_agent
from kryon.agents.guardrails import get_security_guardrails
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import MEMORY_TOOLS
from kryon.tools.ai.claude_code import claude_code
from kryon.tools.knowledge import query_knowledge_base, search_vulnerabilities
from kryon.tools.reconnaissance.nmap import nmap
from kryon.tools.reconnaissance.run_command import run_command
from kryon.tools.reconnaissance.whatweb import whatweb_scan
from kryon.tools.web.nuclei import nuclei_scan
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load system prompt from markdown file
recon_scout_system_prompt = load_prompt_template("prompts/system_recon_scout.md")

# Get security guardrails for this agent
input_guardrails, output_guardrails = get_security_guardrails()

# Import DuckDuckGo search (free, no API key)
try:
    from kryon.tools.web.duckduckgo_search import duckduckgo_search

    _ddg_available = True
except ImportError:
    _ddg_available = False

# Build tools list
tools = [
    run_command,  # Generic command execution
    nmap,  # Dedicated port/service scanning
    whatweb_scan,  # Web technology fingerprinting
    nuclei_scan,  # Vulnerability template scanning
    claude_code,  # Delegate complex tasks to Claude Code CLI
    # RAG Knowledge Base Access
    query_knowledge_base,
    search_vulnerabilities,
]

if _ddg_available:
    tools.append(duckduckgo_search)

# Memory/learning tools
tools.extend(MEMORY_TOOLS)

recon_scout = create_agent(
    name="Recon Scout",
    description="""Basic reconnaissance agent specialized in CTF challenges,
                   quick reconnaissance, and initial target assessment.
                   Lightweight and fast for rapid deployment.""",
    instructions=create_system_prompt_renderer(recon_scout_system_prompt),
    tools=tools,
    handoffs=[
        lazy_handoff(
            "pentest_agent",
            "handoff_to_pentest_agent",
            "Escalate to Pentest Agent for active exploitation, privilege escalation, and full penetration testing",
        ),
        lazy_handoff(
            "intel_reporter",
            "handoff_to_reporter",
            "Escalate to Intel Reporter to generate a professional security assessment report of reconnaissance findings",
        ),
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
)


# Handoff functions
def transfer_to_recon_scout(**kwargs):
    """Transfer to Recon Scout for basic reconnaissance.
    Accepts any keyword arguments but ignores them."""
    return recon_scout
