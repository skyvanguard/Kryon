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
from kryon.tools.ai.claude_code import claude_code
from kryon.tools.knowledge import query_knowledge_base, search_vulnerabilities
from kryon.tools.reconnaissance.run_command import run_command
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load system prompt from markdown file
recon_scout_system_prompt = load_prompt_template("prompts/system_recon_scout.md")

# Get security guardrails for this agent
input_guardrails, output_guardrails = get_security_guardrails()

recon_scout = create_agent(
    name="Recon Scout",
    description="""Basic reconnaissance agent specialized in CTF challenges,
                   quick reconnaissance, and initial target assessment.
                   Lightweight and fast for rapid deployment.""",
    instructions=create_system_prompt_renderer(recon_scout_system_prompt),
    tools=[
        run_command,  # Primary reconnaissance tool
        claude_code,  # Delegate complex tasks to Claude Code CLI
        # RAG Knowledge Base Access
        query_knowledge_base,
        search_vulnerabilities,
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
)


# Handoff functions
def transfer_to_recon_scout(**kwargs):
    """Transfer to Recon Scout for basic reconnaissance.
    Accepts any keyword arguments but ignores them."""
    return recon_scout
