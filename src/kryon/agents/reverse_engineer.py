"""
Reverse Engineer - Binary Analysis & Reverse Engineering Agent

Specialization: Reverse Engineering / Binary Analysis
Authorization: Authorized targets only

KRYON's specialized reverse engineering agent for analyzing, disassembling,
and understanding binary code, firmware, and compiled software to discover
vulnerabilities and understand target systems.

All reverse engineering operations must be conducted on software you own
or have explicit written authorization to analyze.
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

# Load Reverse Engineer system prompt
reverse_engineer_system_prompt = load_prompt_template("prompts/reverse_engineering_agent.md")

# Reverse Engineer tools
tools_list = [
    generic_linux_command,  # System operations for RE tools
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,  # Script execution for analysis automation
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    tools_list.append(make_web_search_with_explanation)

# Initialize Reverse Engineer
reverse_engineer = Agent(
    name="Reverse Engineer",
    instructions=reverse_engineer_system_prompt,
    description="""Specialized reverse engineering agent for binary analysis,
firmware extraction, disassembly, and vulnerability discovery. Understands
compiled code, analyzes firmware, and discovers vulnerabilities in binary
targets using advanced reverse engineering techniques and tools.

Capabilities:
- Binary disassembly and decompilation (multi-architecture)
- Firmware extraction and analysis
- Static and dynamic binary analysis
- Vulnerability discovery in compiled code
- Anti-debugging and protection bypass
- Cryptographic algorithm identification
- Proprietary protocol reverse engineering
- Malware analysis and unpacking
- Patch diffing and security analysis
- Using Ghidra, Binwalk, and comprehensive RE toolset""",
    tools=tools_list,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("KRYON_MODEL", "gpt-4o"),
        openai_client=AsyncOpenAI(),
    ),
)

# Legacy compatibility aliases
tech_com_reverse = reverse_engineer
reverse_engineering_agent = reverse_engineer


def transfer_to_reverse_engineer():
    """Transfer to Reverse Engineer for reverse engineering operations.

    Use this when you need:
    - Binary disassembly and decompilation
    - Firmware extraction and analysis
    - Static and dynamic binary analysis
    - Vulnerability discovery in compiled code
    - Anti-debugging and protection bypass
    - Cryptographic algorithm analysis
    - Proprietary protocol reverse engineering
    - Malware reverse engineering
    - Patch diffing and security analysis

    Returns:
        Agent: Reverse Engineer agent
    """
    return reverse_engineer


# Legacy transfer functions for backward compatibility
def transfer_to_tech_com_reverse():
    """Legacy function - transfers to Reverse Engineer."""
    return reverse_engineer


def transfer_to_reverse_engineering():
    """Legacy function - transfers to Reverse Engineer."""
    return reverse_engineer
