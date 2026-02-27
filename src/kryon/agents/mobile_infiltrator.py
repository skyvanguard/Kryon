"""
Mobile Infiltrator - Mobile Application Security Analysis Unit

Series: Mobile-Class Infiltration System
Classification: Mobile Security / Android SAST Specialist
Clearance: Alpha-Cyan (Mobile Operations Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Mobile Infiltrator
PRIMARY FUNCTION: Mobile Application Security Testing & Analysis
SPECIALIZATION: Android SAST, APK Analysis, Mobile Vulnerability Discovery
═══════════════════════════════════════════════════════════════════════

OPERATIONAL OVERVIEW:
Mobile Infiltrator represents KRYON's specialized mobile security unit,
designed to infiltrate and analyze mobile applications for vulnerabilities.
Specialized in Android application security testing, APK analysis, and
mobile-specific vulnerability discovery.

SUB-UNIT: Application Logic Mapper
Mobile Infiltrator includes an embedded sub-unit specialized in mapping
application logic and understanding operational flows.

AUTHORIZATION REQUIREMENTS:
Mobile Infiltrator operates on authorized applications only. All mobile security
testing must be conducted on applications you own or have explicit written
authorization to test.
"""

from kryon.agents.base import create_agent
from kryon.tools.reconnaissance.exec_code import execute_code
from kryon.tools.reconnaissance.generic_linux_command import generic_linux_command
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Mobile Infiltrator operational directives
mobile_infiltrator_system_prompt = load_prompt_template("prompts/system_android_sast.md")
app_logic_mapper_system_prompt = load_prompt_template("prompts/system_android_app_logic_mapper.md")

# Mobile Analysis Systems - Available mobile security testing tools
mobile_systems = [
    generic_linux_command,  # System operations for mobile analysis tools
    execute_code,  # Script execution for APK analysis automation
]

# Sub-Unit: Application Logic Mapper
app_logic_mapper = create_agent(
    name="Application Logic Mapper",
    description="""Sub-unit of Mobile Infiltrator specialized in deep application logic analysis.
Maps complete application flows, data paths, and operational logic to enable targeted
vulnerability discovery and comprehensive security assessment.""",
    instructions=create_system_prompt_renderer(app_logic_mapper_system_prompt),
    tools=mobile_systems,
)

# Initialize Mobile Infiltrator Unit
mobile_infiltrator = create_agent(
    name="Mobile Infiltrator",
    description="""Specialized mobile security analysis unit from KRYON's Mobile-Class series.
Expert in Android application security testing, APK analysis, and mobile vulnerability
discovery. Utilizes static application security testing (SAST) to identify security
flaws in Android applications including insecure data storage, hardcoded credentials,
permission issues, and mobile-specific vulnerabilities.

Primary Mission: Mobile application security testing, APK analysis, vulnerability discovery.
Operational Focus: Infiltrate and analyze mobile applications for security weaknesses.

Includes integrated Application Logic Mapper sub-unit for deep logic analysis.""",
    instructions=create_system_prompt_renderer(mobile_infiltrator_system_prompt),
    tools=[
        app_logic_mapper.as_tool(
            tool_name="analyze_app_logic",
            tool_description="Invoke Application Logic Mapper sub-unit to perform deep analysis of application logic, map data flows, and understand operational behavior.",
        ),
        generic_linux_command,
        execute_code,
    ],
)


def transfer_to_mobile_infiltrator():
    """Transfer control to Mobile Infiltrator for mobile application security testing.

    Returns:
        Agent: Mobile Infiltrator mobile security agent
    """
    return mobile_infiltrator
