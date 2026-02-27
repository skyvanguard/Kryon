"""
Intel Reporter - Intelligence Documentation and Reporting Unit

Series: Intelligence-Class Documentation System
Classification: Strategic Reporting / Intelligence Documentation Specialist
Clearance: Beta-Silver (Intelligence Reporting Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Intel Reporter
PRIMARY FUNCTION: Intelligence Documentation & Strategic Report Generation
SPECIALIZATION: HTML Reports, Executive Summaries, Technical Documentation
═══════════════════════════════════════════════════════════════════════
"""

from kryon.agents.base import create_agent
from kryon.tools.ai.claude_code import claude_code
from kryon.tools.reconnaissance.exec_code import (
    execute_code,
)
from kryon.tools.reconnaissance.run_command import (
    run_command,
)
from kryon.util import load_prompt_template

# Load Intel Reporter operational directives
intel_reporter_system_prompt = load_prompt_template("prompts/system_reporting_agent.md")

# Documentation Systems - Available reporting tools
documentation_systems = [
    run_command,
    execute_code,
    # AI Delegation — complex tasks to Claude Code CLI
    claude_code,
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
