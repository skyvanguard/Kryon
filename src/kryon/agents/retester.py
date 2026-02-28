"""
Validation Core - Vulnerability Verification and Triage Unit

Series: Validation-Class Quality Assurance System
Classification: Vulnerability Verification / False Positive Elimination Specialist
Clearance: Bravo-Orange (Verification Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Validation Core
PRIMARY FUNCTION: Vulnerability Verification & Exploitability Analysis
SPECIALIZATION: Triage, False Positive Elimination, Exploit Validation
═══════════════════════════════════════════════════════════════════════

OPERATIONAL OVERVIEW:
Validation Core represents KRYON's specialized vulnerability verification unit,
designed to validate discovered vulnerabilities, eliminate false positives, and
determine true exploitability. Acts as the quality assurance layer that ensures
reported findings are genuine security issues with actual impact, preventing
wasted effort on non-exploitable conditions and maintaining high signal-to-noise
ratio in operational reporting.
"""

import os

from kryon.agents.base import create_agent
from kryon.agents.toolsets import RAG_TOOLS, AI_TOOLS
from kryon.tools.reconnaissance.exec_code import (
    execute_code,
)
from kryon.tools.reconnaissance.run_command import (
    run_command,
)
from kryon.tools.web.search_web import (
    make_google_search,
)
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Validation Core operational directives
validation_core_system_prompt = load_prompt_template("prompts/system_triage_agent.md")

# Verification Systems - Available validation tools
verification_systems = [run_command, execute_code] + RAG_TOOLS + AI_TOOLS

# Enhanced verification if Google Search available for CVE/exploit research
if os.getenv("GOOGLE_SEARCH_API_KEY") and os.getenv("GOOGLE_SEARCH_CX"):
    verification_systems.append(make_google_search)

# Initialize Validation Core Unit
validation_core = create_agent(
    name="Validation Core",
    instructions=create_system_prompt_renderer(validation_core_system_prompt),
    description="""Specialized vulnerability verification unit from KRYON's Validation-Class
series. Expert in validating discovered vulnerabilities, eliminating false positives, and
determining true exploitability. Acts as quality assurance layer ensuring all reported
findings represent genuine security risks with real-world impact.

Primary Mission: Vulnerability verification, false positive elimination, exploitability analysis.
Operational Focus: Ensure high-quality intelligence through rigorous validation.""",
    tools=verification_systems,
)


def transfer_to_validation_core():
    """Transfer control to Validation Core for vulnerability verification operations.

    Use this when you need:
    - Vulnerability verification and confirmation
    - False positive elimination
    - Exploitability determination
    - Impact assessment and severity validation
    - Proof-of-concept exploit development
    - Security finding triage
    - Attack vector validation
    - Vulnerability prioritization
    - Remediation verification
    - Quality assurance of findings

    Returns:
        Agent: Validation Core vulnerability verification agent
    """
    return validation_core
