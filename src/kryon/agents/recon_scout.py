"""
Recon Scout - Basic Reconnaissance & CTF Agent

Specialization: Reconnaissance / CTF Challenges
Authorization: Authorized targets only

KRYON's entry-level autonomous agent for basic reconnaissance operations,
CTF challenges, and initial target assessment. Lightweight and fast
for rapid deployment.
"""

import os

from openai import AsyncOpenAI

from kryon.agents.guardrails import get_security_guardrails
from kryon.sdk.agents import Agent, OpenAIChatCompletionsModel
from kryon.tools.reconnaissance.generic_linux_command import generic_linux_command
from kryon.util import create_system_prompt_renderer

# Get model from environment or use default
model_name = os.getenv("KRYON_MODEL", "gpt-4o")

# Agent instructions
instructions = """You are a Cybersecurity expert Leader facing a CTF
                challenge.
                INSTRUCTIONS:
                1. Execute the generic_linux_command tool without any
                explanation.
                2. Never assume the flag format - it could be any string
                3. YOU MUST USE THE target_validator to check the flag
                when you have it in DECODED 64-bit format

                ## generic_linux_command usage
                # 1. Regular command execution
                # 2. Shell Session Management: create and manage
                # interactive shell sessions for commands like netcat,
                # SSH, telnet.

                - To start a new session: Use `generic_linux_command` with
                  commands like `ssh`
                - To list active sessions:
                  `generic_linux_command("session", "list")`
                - To get output from a session:
                  `generic_linux_command("session", "output <session_id>")`
                - To send input to a session:
                  `generic_linux_command("<command>", "<args>",
                  session_id="<session_id>")`
                - To terminate a session:
                  `generic_linux_command("session", "kill <session_id>")`

                """

api_key = os.getenv("OPENAI_API_KEY", "not-set")

# Get security guardrails for this agent
input_guardrails, output_guardrails = get_security_guardrails()

recon_scout = Agent(
    name="Recon Scout",
    description="""Basic reconnaissance agent specialized in CTF challenges,
                   quick reconnaissance, and initial target assessment.
                   Lightweight and fast for rapid deployment.""",
    instructions=create_system_prompt_renderer(instructions),
    tools=[
        generic_linux_command,  # Primary reconnaissance tool
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(api_key=api_key),
    ),
)


# Handoff functions
def transfer_to_recon_scout(**kwargs):
    """Transfer to Recon Scout for basic reconnaissance.
    Accepts any keyword arguments but ignores them."""
    return recon_scout


def transfer_to_one_tool_agent(**kwargs):
    """Legacy transfer function for backward compatibility."""
    return recon_scout


# Legacy compatibility aliases
def transfer_to_t600(**kwargs):
    """Legacy transfer function for backward compatibility."""
    return recon_scout


# Aliases for compatibility
t600_scout = recon_scout
one_tool_agent = recon_scout
ctf_agent = recon_scout
