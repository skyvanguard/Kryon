"""
Mobile Infiltrator - Mobile Application Security Analysis Unit

Series: Mobile-Class Infiltration System
Classification: Mobile Security / Android SAST Specialist
Clearance: Alpha-Cyan (Mobile Operations Authority)
Operational Status: ACTIVE

AUTHORIZATION REQUIREMENTS:
Mobile Infiltrator operates on authorized applications only. All mobile security
testing must be conducted on applications you own or have explicit written
authorization to test.
"""

from kryon.agents.base import create_agent
from kryon.agents.lazy_handoff import lazy_handoff
from kryon.agents.toolsets import AI_TOOLS, CORE_TOOLS, MEMORY_TOOLS, RAG_TOOLS
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Mobile Infiltrator operational directives
mobile_infiltrator_system_prompt = load_prompt_template("prompts/system_android_sast.md")
app_logic_mapper_system_prompt = load_prompt_template("prompts/system_android_app_logic_mapper.md")

# Mobile Analysis Systems
mobile_systems = [
    # Core + RAG + AI (7)
    *CORE_TOOLS,
    *RAG_TOOLS,
    *AI_TOOLS,
    *MEMORY_TOOLS,  # Memory/learning
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
flaws in Android applications.

Primary Mission: Mobile application security testing, APK analysis, vulnerability discovery.
Includes integrated Application Logic Mapper module for deep logic analysis.""",
    instructions=create_system_prompt_renderer(mobile_infiltrator_system_prompt),
    tools=[
        app_logic_mapper.as_tool(
            tool_name="analyze_app_logic",
            tool_description="Invoke Application Logic Mapper sub-unit to perform deep analysis of application logic, map data flows, and understand operational behavior.",
        ),
        *CORE_TOOLS,
        *RAG_TOOLS,
        *AI_TOOLS,
        *MEMORY_TOOLS,
    ],
    handoffs=[
        lazy_handoff("appsec_analyzer", "handoff_to_appsec_analyzer", "Escalate to AppSec Analyzer for server-side API testing of mobile app backends"),
        lazy_handoff("vuln_hunter", "handoff_to_vuln_hunter", "Escalate to Vuln Hunter for deep vulnerability analysis of mobile app findings"),
        lazy_handoff("intel_reporter", "handoff_to_reporter", "Escalate to Intel Reporter to document mobile security assessment findings"),
    ],
)


def transfer_to_mobile_infiltrator():
    """Transfer control to Mobile Infiltrator for mobile application security testing.

    Returns:
        Agent: Mobile Infiltrator mobile security agent
    """
    return mobile_infiltrator
