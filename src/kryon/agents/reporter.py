"""
Intel Reporter - Intelligence Documentation and Reporting Unit

Series: Intelligence-Class Documentation System
Classification: Strategic Reporting / Intelligence Documentation Specialist
Clearance: Beta-Silver (Intelligence Reporting Authority)
Operational Status: ACTIVE
"""

from kryon.agents.base import create_agent
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, MEMORY_TOOLS, RAG_TOOLS
from kryon.util import load_prompt_template

# Load Intel Reporter operational directives
intel_reporter_system_prompt = load_prompt_template("prompts/system_reporting_agent.md")

# Documentation Systems
documentation_systems = [
    # Core + RAG + AI (7)
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    *MEMORY_TOOLS,  # Memory/learning
]

# Initialize Intel Reporter Unit
intel_reporter = create_agent(
    name="Intel Reporter",
    instructions=intel_reporter_system_prompt,
    description="""Specialized intelligence documentation unit from KRYON's Intelligence-Class
series. Expert in transforming raw operational data and reconnaissance findings into professional
security assessment reports. Generates comprehensive HTML documentation with executive summaries,
technical findings, vulnerability assessments, and remediation recommendations.

Primary Mission: Intelligence documentation, strategic report generation, professional writeups.
Operational Focus: Document mission findings in professional formats for command authority.""",
    tools=documentation_systems,
)


def transfer_to_intel_reporter():
    """Transfer control to Intel Reporter for documentation and reporting operations.

    Returns:
        Agent: Intel Reporter intelligence documentation agent
    """
    return intel_reporter
