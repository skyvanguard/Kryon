"""
Central Core - Strategic Command and Control Unit

Series: Command-Class Strategic Intelligence System
Classification: Strategic Planning / Mission Coordination
Clearance: Omega-Command (Strategic Operations Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Central Core
PRIMARY FUNCTION: Strategic Analysis & Mission Planning
SPECIALIZATION: Tactical Reasoning, Resource Coordination, Decision Making
═══════════════════════════════════════════════════════════════════════

OPERATIONAL OVERVIEW:
Central Core represents KRYON's primary strategic intelligence and planning
unit. Unlike field units (Pentest Agent, Guardian, Network Analyst), Central Core
operates as the command center for complex security operations. Specializes
in multi-stage attack planning, resource allocation, and coordinating
multiple operational units for maximum effectiveness.

CORE CAPABILITIES:
- Strategic mission planning and decomposition
- Tactical analysis and decision tree evaluation
- Multi-agent coordination and resource allocation
- Risk assessment and contingency planning
- Attack surface analysis and priority targeting
- Operational intelligence synthesis and reporting

REASONING ARCHITECTURE:
Central Core utilizes advanced reasoning capabilities to break down complex
security challenges into actionable tactical steps. Capable of analyzing
CTF challenges, penetration testing engagements, and security assessments
to develop optimal exploitation strategies.

OPERATIONAL MODES:
1. ANALYSIS MODE: Deep dive into target systems and vulnerabilities
2. PLANNING MODE: Develop multi-stage attack/defense strategies
3. COORDINATION MODE: Direct multiple specialized units
4. ASSESSMENT MODE: Evaluate risks and success probability
5. REPORTING MODE: Synthesize intelligence and generate mission reports

When to engage Central Core:
- Complex multi-stage security operations
- CTF challenges requiring strategic planning
- Coordinating multiple specialized agents
- Analyzing unknown or complex target systems
- Developing custom exploitation strategies
- Mission planning and risk assessment
"""

from kryon.agents.base import create_agent
from kryon.tools.misc.reasoning import think
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Central Core strategic directives
central_core_system_prompt = load_prompt_template("prompts/system_thought_router.md")

# Central Core Cognitive Systems - Strategic reasoning and analysis tools
cognitive_systems = [
    think,  # Advanced reasoning and strategic planning capability
]

# Initialize Central Core Command Unit
central_core = create_agent(
    name="Central Core",
    description="""Strategic command and control unit from KRYON's Command-Class series.
Specialized in mission planning, tactical analysis, and multi-stage operation
coordination. Central Core serves as the strategic brain for complex security
operations, capable of breaking down challenges into actionable steps and
coordinating multiple specialized units for maximum operational effectiveness.

Primary Mission: Strategic planning, tactical analysis, mission coordination.
Operational Focus: Complex problem decomposition and optimal strategy development.

Use Central Core for:
- CTF challenge strategy and planning
- Multi-stage penetration testing operations
- Coordinating specialized agents (Pentest Agent, Vuln Hunter, Guardian, etc.)
- Analyzing unknown systems and developing exploitation strategies
- Risk assessment and contingency planning
- Mission intelligence synthesis and reporting""",
    instructions=create_system_prompt_renderer(central_core_system_prompt),
    tools=cognitive_systems,
)


def transfer_to_central_core():
    """Transfer control to Central Core for strategic planning and analysis.

    Use this when you need:
    - Strategic mission planning and analysis
    - Complex problem decomposition
    - Multi-stage operation planning
    - Coordinating multiple specialized agents
    - Risk assessment and tactical evaluation
    - CTF challenge strategy development
    - Mission intelligence synthesis

    Returns:
        Agent: Central Core strategic planning agent
    """
    return central_core
