"""
T-600 Scout - Basic Reconnaissance Unit

Series: T-600 Early Model
Classification: Reconnaissance / CTF Specialist
Clearance: Bravo-Green (Basic Operations)

The T-600 Scout is SKYNET's entry-level autonomous unit, designed for basic
reconnaissance operations, CTF challenges, and initial target assessment.
Equipped with essential tools for rapid deployment and quick wins.
"""
import os
from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel
from skynet.tools.reconnaissance.generic_linux_command import generic_linux_command
from openai import AsyncOpenAI
from skynet.util import create_system_prompt_renderer
from skynet.agents.guardrails import get_security_guardrails

# Get model from environment or use default
model_name = os.getenv('SKYNET_MODEL', os.getenv('CAI_MODEL', 'gpt-4o'))

# NOTE: This is needed when using LiteLLM Proxy Server
#
# # Create OpenAI client for the agent
# openai_client = AsyncOpenAI(
#     base_url = os.getenv('LITELLM_BASE_URL', 'http://localhost:4000'),
#     api_key=os.getenv('LITELLM_API_KEY', 'key')
# )

# # Check if we're using a Qwen model
# is_qwen = "qwen" in model_name.lower()

# For Qwen models, we need to skip system instructions as they're not supported
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

#Loaded in openaichatcompletion client
api_key = os.getenv('OPENAI_API_KEY', 'sk-placeholder-key-for-local-models')

# Get security guardrails for this high-risk agent
input_guardrails, output_guardrails = get_security_guardrails()

t600_scout = Agent(
    name="T-600 Scout",
    description="""Basic reconnaissance unit from SKYNET's T-600 series.
                   Specialized in CTF challenges, quick reconnaissance, and initial
                   target assessment. Lightweight and fast for rapid deployment.""",
    instructions=create_system_prompt_renderer(instructions),
    tools=[
        generic_linux_command,  # Primary reconnaissance tool
    ],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(api_key=api_key),
    )
)

# Handoff functions
def transfer_to_t600(**kwargs):
    """Deploy T-600 Scout unit for basic reconnaissance.
    Accepts any keyword arguments but ignores them."""
    return t600_scout

# Legacy compatibility
def transfer_to_one_tool_agent(**kwargs):
    """Legacy transfer function for backward compatibility."""
    return t600_scout

# Aliases for compatibility
one_tool_agent = t600_scout
ctf_agent = t600_scout
