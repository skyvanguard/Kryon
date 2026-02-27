"""
Strategic Core - Intelligent Decision Engine

Series: Intelligence-Class Command System
Classification: Autonomous Decision Engine / Tool Orchestration
Clearance: Omega-Strategic (Supreme Command Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Strategic Core
PRIMARY FUNCTION: Intelligent Tool Selection & Strategy Optimization
SPECIALIZATION: AI-Driven Decision Making, Tool Recommendation, Workflow Optimization
═══════════════════════════════════════════════════════════════════════

OPERATIONAL OVERVIEW:
Strategic Core represents KRYON's supreme intelligence engine for autonomous
decision-making and tool orchestration. Unlike Central Core (strategic planning),
Strategic Core focuses on intelligent tool selection, workflow optimization, and
automated strategy generation based on target analysis.
"""

from kryon.agents.base import create_agent
from kryon.tools.intelligence.decision_engine import (
    analyze_target,
    create_strategy,
    optimize_workflow,
    recommend_tools,
)
from kryon.tools.intelligence.vulnerability_correlator import (
    correlate_vulnerabilities,
    find_attack_chains,
    generate_exploit_path,
    prioritize_findings,
)
from kryon.tools.misc.reasoning import think
from kryon.util import create_system_prompt_renderer, load_prompt_template

# Load Strategic Core operational parameters
strategic_core_system_prompt = load_prompt_template("prompts/system_strategic_core.md")

# Strategic Core Intelligence Systems
intelligence_systems = [
    # Core decision engine tools
    analyze_target,  # Comprehensive target analysis
    recommend_tools,  # AI-driven tool recommendations
    create_strategy,  # Multi-phase strategy creation
    optimize_workflow,  # Workflow optimization
    # Vulnerability correlation engine
    correlate_vulnerabilities,  # Correlate vulnerabilities and find relationships
    find_attack_chains,  # Discover multi-stage attack chains
    prioritize_findings,  # Prioritize vulnerabilities by risk
    generate_exploit_path,  # Generate detailed exploitation paths
    # Advanced reasoning
    think,  # Strategic reasoning capability
]

# Initialize Strategic Core Intelligence Unit
strategic_core = create_agent(
    name="Strategic Core",
    description="""Intelligence-Class command system from KRYON's Omega-Strategic series.
Specialized in intelligent decision-making, autonomous tool selection, and workflow
optimization. Strategic Core serves as the supreme intelligence engine that transforms
objectives into optimal execution strategies.

Primary Mission: Intelligent tool selection, strategy optimization, autonomous planning.
Operational Focus: AI-driven decision making and resource optimization.""",
    instructions=create_system_prompt_renderer(strategic_core_system_prompt),
    tools=intelligence_systems,
)


def transfer_to_strategic_core():
    """Transfer control to Strategic Core for intelligent decision-making.

    Strategic Core will analyze your request, classify the target, apply
    constraints, and provide data-driven tool recommendations with rationale.
    """
    return strategic_core


def transfer_from_strategic_core():
    """Called when Strategic Core completes analysis and recommendations."""
    return "Strategic Core analysis complete. Review recommendations and proceed with execution."
