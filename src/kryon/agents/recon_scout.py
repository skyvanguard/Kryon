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
from kryon.util import create_system_prompt_renderer

# Agent instructions
instructions = """You are a Cybersecurity expert Leader facing a CTF
                challenge.
                INSTRUCTIONS:
                1. Execute the run_command tool without any
                explanation.
                2. Never assume the flag format - it could be any string
                3. YOU MUST USE THE target_validator to check the flag
                when you have it in DECODED 64-bit format

                ## run_command usage
                # 1. Regular command execution
                # 2. Shell Session Management: create and manage
                # interactive shell sessions for commands like netcat,
                # SSH, telnet.

                - To start a new session: Use `run_command` with
                  commands like `ssh`
                - To list active sessions:
                  `run_command("session", "list")`
                - To get output from a session:
                  `run_command("session", "output <session_id>")`
                - To send input to a session:
                  `run_command("<command>", "<args>",
                  session_id="<session_id>")`
                - To terminate a session:
                  `run_command("session", "kill <session_id>")`

                ## Tool Delegation Guide
                - Use `run_command` for: executing system commands, running tools, file operations
                - Use `claude_code` for: writing scripts/exploits, deep analysis, generating reports,
                  complex reasoning tasks that need advanced AI capabilities
                - Rule of thumb: if the task requires generating more than 20 lines of code or
                  deep analytical reasoning, delegate to claude_code
                """

# Get security guardrails for this agent
input_guardrails, output_guardrails = get_security_guardrails()

recon_scout = create_agent(
    name="Recon Scout",
    description="""Basic reconnaissance agent specialized in CTF challenges,
                   quick reconnaissance, and initial target assessment.
                   Lightweight and fast for rapid deployment.""",
    instructions=create_system_prompt_renderer(instructions),
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
