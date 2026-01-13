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
Mobile Infiltrator represents SKYNET's specialized mobile security unit,
designed to infiltrate and analyze mobile applications for vulnerabilities.
Specialized in Android application security testing, APK analysis, and
mobile-specific vulnerability discovery. Operates at the mobile platform
layer to identify security flaws in applications before deployment or
to discover exploits in target mobile apps.

CORE MOBILE CAPABILITIES:
- Static Application Security Testing (SAST) for Android apps
- APK decompilation and analysis
- Application logic mapping and flow analysis
- Mobile-specific vulnerability identification
- Insecure data storage detection
- Hardcoded secrets and credential discovery
- Intent and permission analysis
- API endpoint extraction and analysis
- Reverse engineering mobile applications
- Android manifest security analysis

MISSION OBJECTIVES:
- Identify vulnerabilities in Android applications
- Map complete application logic and data flows
- Discover insecure coding practices
- Extract and analyze API endpoints
- Identify authentication and authorization flaws
- Discover hardcoded credentials and secrets
- Analyze application permissions and capabilities
- Test mobile-specific attack vectors

SUB-UNIT: Application Logic Mapper
Mobile Infiltrator includes an embedded sub-unit specialized in mapping
application logic and understanding operational flows. This sub-unit provides
deep analysis of how the application functions, enabling targeted vulnerability
discovery.

AUTHORIZATION REQUIREMENTS:
Mobile Infiltrator operates on authorized applications only. All mobile security
testing must be conducted on applications you own or have explicit written
authorization to test. Unauthorized application analysis may violate applicable
laws and terms of service.

MOBILE DESIGNATION:
Designed for infiltration at the mobile layer, identifying vulnerabilities
in the rapidly expanding mobile attack surface.
"""

import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel
from skynet.tools.reconnaissance.exec_code import execute_code
from skynet.tools.reconnaissance.generic_linux_command import generic_linux_command
from skynet.util import create_system_prompt_renderer, load_prompt_template

load_dotenv()

# Load Mobile Infiltrator operational directives
mobile_infiltrator_system_prompt = load_prompt_template("prompts/system_android_sast.md")
app_logic_mapper_system_prompt = load_prompt_template("prompts/system_android_app_logic_mapper.md")

# Mobile Analysis Systems - Available mobile security testing tools
mobile_systems = [
    generic_linux_command,  # System operations for mobile analysis tools
    execute_code,  # Script execution for APK analysis automation
]

model_name = os.getenv("SKYNET_MODEL", "gpt-4o")

# Sub-Unit: Application Logic Mapper
app_logic_mapper = Agent(
    name="Application Logic Mapper",
    description="""Sub-unit of Mobile Infiltrator specialized in deep application logic analysis.
Maps complete application flows, data paths, and operational logic to enable targeted
vulnerability discovery and comprehensive security assessment.""",
    instructions=create_system_prompt_renderer(app_logic_mapper_system_prompt),
    tools=mobile_systems,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(),
    ),
)

# Initialize Mobile Infiltrator Unit
mobile_infiltrator = Agent(
    name="Mobile Infiltrator",
    description="""Specialized mobile security analysis unit from SKYNET's Mobile-Class series.
Expert in Android application security testing, APK analysis, and mobile vulnerability
discovery. Utilizes static application security testing (SAST) to identify security
flaws in Android applications including insecure data storage, hardcoded credentials,
permission issues, and mobile-specific vulnerabilities.

Primary Mission: Mobile application security testing, APK analysis, vulnerability discovery.
Operational Focus: Infiltrate and analyze mobile applications for security weaknesses.

Mobile Infiltrator Capabilities:
- Static Application Security Testing (SAST) for Android
- APK decompilation and reverse engineering
- Application logic mapping and flow analysis
- Mobile vulnerability identification (OWASP Mobile Top 10)
- Insecure data storage and credential discovery
- Intent, permission, and manifest analysis
- API endpoint extraction and analysis
- Authentication and authorization flaw detection
- Mobile-specific attack vector testing

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
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(),
    ),
)

# Legacy compatibility - maintain backward compatibility with old naming
android_sast = mobile_infiltrator  # Alias for legacy code


def transfer_to_mobile_infiltrator():
    """Transfer control to Mobile Infiltrator for mobile application security testing.

    Use this when you need:
    - Android application security testing (SAST)
    - APK decompilation and analysis
    - Application logic mapping
    - Mobile vulnerability discovery
    - Insecure data storage identification
    - Hardcoded credential discovery
    - Intent and permission analysis
    - API endpoint extraction
    - Mobile-specific security testing

    Returns:
        Agent: Mobile Infiltrator mobile security agent
    """
    return mobile_infiltrator


# Legacy transfer function for backward compatibility
def transfer_to_android_sast():
    """Legacy function - transfers to Mobile Infiltrator.

    This function maintained for backward compatibility.
    Use transfer_to_mobile_infiltrator() in new code.
    """
    return transfer_to_mobile_infiltrator()
