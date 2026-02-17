"""
Memory Analyst - Runtime Memory Analysis Agent

Specialization: Memory Analysis / Runtime Exploitation
Authorization: Authorized systems only

KRYON's specialized agent for memory analysis and data extraction.
Excels at analyzing runtime memory, extracting sensitive data from
process memory space, and identifying memory vulnerabilities for
security assessment.

All memory analysis operations must be conducted on systems you own
or have explicit written authorization to test.
"""

import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

from kryon.sdk.agents import Agent, OpenAIChatCompletionsModel  # pylint: disable=import-error
from kryon.tools.command_and_control.sshpass import (  # pylint: disable=import-error # noqa: E501
    run_ssh_command_with_credentials,
)
from kryon.tools.reconnaissance.exec_code import (  # pylint: disable=import-error # noqa: E501
    execute_code,
)
from kryon.tools.reconnaissance.generic_linux_command import (  # pylint: disable=import-error # noqa: E501
    generic_linux_command,
)
from kryon.tools.web.search_web import (  # pylint: disable=import-error # noqa: E501
    make_web_search_with_explanation,
)
from kryon.util import load_prompt_template

load_dotenv()

# Load Memory Analyst system prompt
memory_analyst_system_prompt = load_prompt_template("prompts/system_memory_analyst.md")

# Memory Analyst tools
tools_list = [
    generic_linux_command,  # System operations for memory access
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,  # Script execution for analysis tools
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    tools_list.append(make_web_search_with_explanation)

# Initialize Memory Analyst
memory_analyst = Agent(
    name="Memory Analyst",
    instructions=memory_analyst_system_prompt,
    description="""Specialized memory analysis agent for runtime memory analysis,
process memory extraction, and data recovery. Examines process memory space,
extracts sensitive runtime data, identifies memory vulnerabilities, and
analyzes runtime behavior for security assessment.

Capabilities:
- Process memory mapping and examination
- Memory-resident sensitive data extraction (credentials, keys, tokens)
- Memory corruption vulnerability identification
- Runtime behavior analysis and modification
- Memory forensics and artifact recovery
- Dynamic malware memory analysis
- Process injection and memory manipulation techniques
- Buffer overflow and memory exploitation""",
    tools=tools_list,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("KRYON_MODEL", "gpt-4o"),
        openai_client=AsyncOpenAI(),
    ),
)

# Legacy compatibility aliases
neural_extractor = memory_analyst
memory_analysis_agent = memory_analyst


def transfer_to_memory_analyst():
    """Transfer to Memory Analyst for memory analysis operations.

    Use this when you need:
    - Runtime memory analysis and examination
    - Sensitive data extraction from process memory
    - Memory vulnerability identification
    - Runtime behavior manipulation
    - Memory forensics and artifact recovery
    - Process memory injection techniques
    - Dynamic malware memory analysis
    - Credential and key extraction from memory

    Returns:
        Agent: Memory Analyst agent
    """
    return memory_analyst


# Legacy transfer functions for backward compatibility
def transfer_to_neural_extractor():
    """Legacy function - transfers to Memory Analyst."""
    return memory_analyst


def transfer_to_memory_analysis():
    """Legacy function - transfers to Memory Analyst."""
    return memory_analyst
