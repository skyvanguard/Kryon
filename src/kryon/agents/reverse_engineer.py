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

from kryon.agents.base import create_agent
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.tools.ai.claude_code import claude_code
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)
from kryon.tools.knowledge import get_exploit_techniques, query_knowledge_base, search_vulnerabilities
from kryon.tools.reconnaissance.exec_code import (
    execute_code,
)
from kryon.tools.reconnaissance.run_command import (
    run_command,
)
from kryon.tools.web.search_web import (
    make_web_search_with_explanation,
)
from kryon.agents.toolsets import MEMORY_TOOLS
from kryon.util import load_prompt_template

# Load Reverse Engineer system prompt
reverse_engineer_system_prompt = load_prompt_template("prompts/reverse_engineering_agent.md")

# Reverse Engineer tools
tools_list = [
    run_command,  # System operations for RE tools
    run_ssh_command_with_credentials,  # Remote system access
    execute_code,  # Script execution for analysis automation
    # RAG Knowledge Base Access
    query_knowledge_base,
    search_vulnerabilities,
    get_exploit_techniques,
    # AI Delegation — complex tasks to Claude Code CLI
    claude_code,
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    tools_list.append(make_web_search_with_explanation)

# Memory/learning tools
tools_list.extend(MEMORY_TOOLS)

# Initialize Reverse Engineer
reverse_engineer = create_agent(
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
    handoffs=[
        lazy_handoff("vuln_hunter", "handoff_to_vuln_hunter", "Escalate to Vuln Hunter when reverse engineering reveals exploitable vulnerabilities"),
        lazy_handoff("exploit_validator", "handoff_to_exploit_validator", "Escalate to Exploit Validator to validate vulnerabilities found during binary analysis"),
        lazy_handoff("intel_reporter", "handoff_to_reporter", "Escalate to Intel Reporter to document reverse engineering findings"),
    ],
)


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
