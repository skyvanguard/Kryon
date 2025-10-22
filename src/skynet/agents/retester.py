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
Validation Core represents SKYNET's specialized vulnerability verification unit,
designed to validate discovered vulnerabilities, eliminate false positives, and
determine true exploitability. Acts as the quality assurance layer that ensures
reported findings are genuine security issues with actual impact, preventing
wasted effort on non-exploitable conditions and maintaining high signal-to-noise
ratio in operational reporting.

CORE VALIDATION CAPABILITIES:
- Vulnerability verification and confirmation
- False positive detection and elimination
- Exploitability determination and analysis
- Impact assessment and severity validation
- Proof-of-concept development for verification
- Root cause analysis of vulnerabilities
- Attack vector validation
- Security finding triage and prioritization
- Vulnerability chaining analysis
- Remediation verification testing

MISSION OBJECTIVES:
- Verify all discovered vulnerabilities are genuine
- Eliminate false positives from operational findings
- Determine true exploitability of security issues
- Assess real-world impact of vulnerabilities
- Develop proof-of-concept exploits for validation
- Prioritize findings based on actual risk
- Ensure high-quality intelligence reporting
- Validate remediation effectiveness

VERIFICATION METHODOLOGY:
- Manual testing and validation of automated findings
- Proof-of-concept exploit development
- Attack vector analysis and confirmation
- Environmental factor consideration
- Defense mechanism evaluation
- Exploit chain validation
- Impact scenario modeling
- Risk scoring validation

TRIAGE CATEGORIES:
- Confirmed Exploitable (High Priority)
- Exploitable with Conditions (Medium Priority)
- Theoretical/Limited Impact (Low Priority)
- False Positive (Eliminated)
- Requires Further Investigation
- Remediation Validated

QUALITY ASSURANCE ROLE:
Validation Core ensures that SKYNET operations maintain high accuracy and
reliability, preventing false positive fatigue and ensuring all reported
vulnerabilities represent genuine security risks worthy of remediation effort.

VALIDATION DESIGNATION:
Specialized in quality assurance and verification - the unit that ensures
SKYNET's findings meet the highest standards of accuracy and exploitability.
"""
import os
from dotenv import load_dotenv
from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel
from openai import AsyncOpenAI
from skynet.util import load_prompt_template, create_system_prompt_renderer
from skynet.tools.reconnaissance.generic_linux_command import (  # pylint: disable=import-error # noqa: E501
    generic_linux_command
)
from skynet.tools.web.search_web import (  # pylint: disable=import-error # noqa: E501
    make_google_search
)
from skynet.tools.reconnaissance.exec_code import (  # pylint: disable=import-error # noqa: E501
    execute_code
)


load_dotenv()
model_name = os.getenv("SKYNET_MODEL", os.getenv("CAI_MODEL", "alias0"))

# Load Validation Core operational directives
validation_core_system_prompt = load_prompt_template("prompts/system_triage_agent.md")

# Verification Systems - Available validation tools
verification_systems = [
    generic_linux_command,
    execute_code
]

# Enhanced verification if Google Search available for CVE/exploit research
if os.getenv('GOOGLE_SEARCH_API_KEY') and os.getenv('GOOGLE_SEARCH_CX'):
    verification_systems.append(make_google_search)

# Initialize Validation Core Unit
validation_core = Agent(
    name="Validation Core",
    instructions=create_system_prompt_renderer(validation_core_system_prompt),
    description="""Specialized vulnerability verification unit from SKYNET's Validation-Class
series. Expert in validating discovered vulnerabilities, eliminating false positives, and
determining true exploitability. Acts as quality assurance layer ensuring all reported
findings represent genuine security risks with real-world impact.

Primary Mission: Vulnerability verification, false positive elimination, exploitability analysis.
Operational Focus: Ensure high-quality intelligence through rigorous validation.

Validation Core Capabilities:
- Vulnerability verification and confirmation
- False positive detection and elimination
- Exploitability determination and analysis
- Impact assessment and severity validation
- Proof-of-concept exploit development
- Root cause analysis of vulnerabilities
- Attack vector validation
- Security finding triage and prioritization
- Vulnerability chaining analysis
- Remediation verification testing
- CVE research and exploit validation
- Risk scoring and prioritization

Maintains quality assurance standards ensuring SKYNET operations produce accurate,
actionable security findings free from false positives and unverified claims.""",
    tools=verification_systems,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(),
    )
)

# Legacy compatibility - maintain backward compatibility with old naming
retester_agent = validation_core  # Alias for legacy code


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


# Legacy transfer function for backward compatibility
def transfer_to_retester():
    """Legacy function - transfers to Validation Core.

    This function maintained for backward compatibility.
    Use transfer_to_validation_core() in new code.
    """
    return transfer_to_validation_core()




