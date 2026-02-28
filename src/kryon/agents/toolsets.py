"""
Shared toolsets for KRYON agents.

Provides standardized tool groupings to ensure consistent capabilities
across all agents while keeping individual tool lists focused.
"""

from kryon.tools.ai.claude_code import claude_code
from kryon.tools.knowledge import (
    get_exploit_techniques,
    get_security_tools,
    query_knowledge_base,
    search_vulnerabilities,
)
from kryon.tools.reconnaissance.exec_code import execute_code
from kryon.tools.reconnaissance.run_command import run_command

# Core execution tools — every agent that runs commands needs these
CORE_TOOLS = [run_command, execute_code]

# RAG knowledge base tools — basic set for most agents
RAG_TOOLS = [query_knowledge_base, search_vulnerabilities]

# RAG full set — for agents doing deep vuln research
RAG_TOOLS_FULL = RAG_TOOLS + [get_exploit_techniques, get_security_tools]

# AI delegation tool
AI_TOOLS = [claude_code]

# Base toolset — standard for every agent (7 tools)
BASE_TOOLS = CORE_TOOLS + RAG_TOOLS + AI_TOOLS
