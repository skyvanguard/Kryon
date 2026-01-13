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

OPERATIONAL OVERVIEW:
Intel Reporter represents SKYNET's specialized intelligence documentation unit,
designed to transform raw operational data and reconnaissance findings into
professional, actionable security assessment reports. Generates comprehensive
HTML documentation that presents technical findings in both executive and
technical formats, ensuring mission intelligence is properly documented and
communicated to command authority.

CORE REPORTING CAPABILITIES:
- Professional HTML report generation
- Executive summary creation
- Technical findings documentation
- Vulnerability assessment reports
- Penetration testing documentation
- Security posture assessments
- Multi-format report generation
- Evidence documentation and presentation
- Timeline and attack chain visualization
- Recommendation and remediation planning

MISSION OBJECTIVES:
- Document operational findings comprehensively
- Generate professional security assessment reports
- Present technical data in accessible formats
- Create executive summaries for leadership
- Maintain operational documentation standards
- Preserve intelligence for future operations
- Support compliance and audit requirements
- Enable knowledge transfer and training

REPORT CATEGORIES:
- Penetration Testing Reports
- Vulnerability Assessment Reports
- Red Team Operation Reports
- Security Audit Documentation
- Incident Response Reports
- Forensic Analysis Reports
- CTF Challenge Writeups
- Bug Bounty Submissions

DOCUMENTATION STANDARDS:
Intel Reporter maintains professional standards for all documentation,
ensuring reports meet industry best practices (PTES, OWASP, NIST) and
provide actionable intelligence for security improvement.

INTEL DESIGNATION:
Specialized in transforming raw operational data into professional intelligence
documentation - the unit that ensures SKYNET's findings are properly recorded
and communicated.
"""

import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel  # pylint: disable=import-error
from skynet.tools.reconnaissance.exec_code import (  # pylint: disable=import-error # noqa: E501
    execute_code,
)
from skynet.tools.reconnaissance.generic_linux_command import (  # pylint: disable=import-error # noqa: E501
    generic_linux_command,
)
from skynet.util import load_prompt_template

load_dotenv()
model_name = os.getenv("SKYNET_MODEL", "gpt-4o")

# Load Intel Reporter operational directives
intel_reporter_system_prompt = load_prompt_template("prompts/system_reporting_agent.md")

# Documentation Systems - Available reporting tools
documentation_systems = [
    generic_linux_command,
    execute_code,
]

# Initialize Intel Reporter Unit
intel_reporter = Agent(
    name="Intel Reporter",
    instructions=intel_reporter_system_prompt,
    description="""Specialized intelligence documentation unit from SKYNET's Intelligence-Class
series. Expert in transforming raw operational data and reconnaissance findings into professional
security assessment reports. Generates comprehensive HTML documentation with executive summaries,
technical findings, vulnerability assessments, and remediation recommendations.

Primary Mission: Intelligence documentation, strategic report generation, professional writeups.
Operational Focus: Document mission findings in professional formats for command authority.

Intel Reporter Capabilities:
- Professional HTML report generation
- Executive summary creation for leadership
- Technical findings documentation
- Vulnerability assessment reports
- Penetration testing documentation
- Security audit reports
- Incident response documentation
- CTF writeups and challenge documentation
- Evidence presentation and visualization
- Remediation planning and recommendations
- Multi-format report generation
- Compliance and audit documentation

Maintains documentation standards aligned with industry frameworks (PTES, OWASP, NIST) and
ensures all operational intelligence is properly recorded and communicated.""",
    tools=documentation_systems,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(),
    ),
)

# Legacy compatibility - maintain backward compatibility with old naming
reporting_agent = intel_reporter  # Alias for legacy code


def transfer_to_intel_reporter():
    """Transfer control to Intel Reporter for documentation and reporting operations.

    Use this when you need:
    - Professional security assessment reports
    - HTML report generation
    - Executive summary creation
    - Vulnerability assessment documentation
    - Penetration testing reports
    - Technical findings documentation
    - Incident response reports
    - CTF writeups and documentation
    - Compliance and audit reports
    - Evidence documentation

    Returns:
        Agent: Intel Reporter intelligence documentation agent
    """
    return intel_reporter


# Legacy transfer function for backward compatibility
def transfer_to_reporting_agent():
    """Legacy function - transfers to Intel Reporter.

    This function maintained for backward compatibility.
    Use transfer_to_intel_reporter() in new code.
    """
    return transfer_to_intel_reporter()
