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

from kryon.agents.base import create_agent
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, MEMORY_TOOLS, RAG_TOOLS
from kryon.tools.command_and_control.sshpass import (
    run_ssh_command_with_credentials,
)
from kryon.tools.knowledge import get_exploit_techniques
from kryon.tools.web.search_web import (
    make_web_search_with_explanation,
)
from kryon.util import load_prompt_template

# Load Memory Analyst system prompt
memory_analyst_system_prompt = load_prompt_template("prompts/system_memory_analyst.md")

# Memory Analyst tools
tools_list = [
    # Core + RAG + AI (7)
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    # Memory/learning
    *MEMORY_TOOLS,
    # Remote access
    run_ssh_command_with_credentials,
    # Additional RAG — exploit techniques for memory attacks
    get_exploit_techniques,
]

# Enhanced intelligence gathering if Perplexity API available
if os.getenv("PERPLEXITY_API_KEY"):
    tools_list.append(make_web_search_with_explanation)

# Initialize Memory Analyst
memory_analyst = create_agent(
    name="Memory Analyst",
    instructions=memory_analyst_system_prompt,
    description="""Specialized memory analysis agent for runtime memory analysis,
process memory extraction, and data recovery. Examines process memory space,
extracts sensitive runtime data, identifies memory vulnerabilities, and
analyzes runtime behavior for security assessment.""",
    tools=tools_list,
    handoffs=[
        lazy_handoff("forensic_analyzer", "handoff_to_forensic_analyzer", "Escalate to Forensic Analyzer for full forensic investigation when memory analysis reveals compromise"),
        lazy_handoff("reverse_engineer", "handoff_to_reverse_engineer", "Escalate to Reverse Engineer for binary analysis of suspicious processes found in memory"),
        lazy_handoff("intel_reporter", "handoff_to_reporter", "Escalate to Intel Reporter to document memory analysis findings"),
    ],
)


def transfer_to_memory_analyst():
    """Transfer to Memory Analyst for memory analysis operations.

    Returns:
        Agent: Memory Analyst agent
    """
    return memory_analyst
