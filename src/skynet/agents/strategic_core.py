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
Strategic Core represents SKYNET's supreme intelligence engine for autonomous
decision-making and tool orchestration. Unlike Central Core (strategic planning),
Strategic Core focuses on intelligent tool selection, workflow optimization, and
automated strategy generation based on target analysis.

This unit bridges the gap between human intent and autonomous execution by:
- Automatically analyzing targets and classifying them
- Selecting optimal tools based on context, constraints, and objectives
- Creating multi-phase execution strategies
- Optimizing tool workflows for parallel execution
- Coordinating multiple agents with intelligent task distribution

CORE CAPABILITIES:
- Intelligent target analysis and classification
- Context-aware tool recommendation engine
- Multi-phase strategy generation
- Workflow optimization and parallelization
- Resource allocation and constraint handling
- Success probability estimation
- Adaptive strategy refinement

DECISION INTELLIGENCE:
Strategic Core uses an advanced decision engine with:
- Tool capability database (50+ security tools)
- Constraint-based filtering (stealth, speed, accuracy)
- Objective-capability matching algorithms
- Parallel execution opportunity identification
- Resource optimization logic
- Risk assessment calculations

OPERATIONAL MODES:
1. ANALYSIS MODE: Analyze target and recommend strategy
2. TOOL SELECTION MODE: Recommend optimal tools for objectives
3. STRATEGY MODE: Create comprehensive multi-phase plans
4. OPTIMIZATION MODE: Optimize tool execution workflows
5. COORDINATION MODE: Distribute tasks across agents

When to engage Strategic Core:
- Need optimal tool selection for specific objectives
- Require multi-phase penetration testing strategy
- Want to optimize tool execution workflow
- Need intelligent agent coordination
- Require constraint-based tool filtering (stealth, time, etc.)
- Want automated target analysis and classification
"""

from skynet.tools.intelligence.decision_engine import (
    analyze_target,
    recommend_tools,
    create_strategy,
    optimize_workflow
)
from skynet.tools.misc.reasoning import think
from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel
from openai import AsyncOpenAI
from skynet.util import load_prompt_template, create_system_prompt_renderer
import os

# Load Strategic Core operational parameters
strategic_core_system_prompt = load_prompt_template("prompts/system_strategic_core.md")

# Strategic Core Intelligence Systems
intelligence_systems = [
    # Core decision engine tools
    analyze_target,      # Comprehensive target analysis
    recommend_tools,     # AI-driven tool recommendations
    create_strategy,     # Multi-phase strategy creation
    optimize_workflow,   # Workflow optimization

    # Advanced reasoning
    think,              # Strategic reasoning capability
]

# Initialize Strategic Core Intelligence Unit
strategic_core = Agent(
    name="Strategic Core",
    model=OpenAIChatCompletionsModel(
        model=os.getenv('SKYNET_MODEL', os.getenv('CAI_MODEL', "alias0")),
        openai_client=AsyncOpenAI(),
    ),
    description="""Intelligence-Class command system from SKYNET's Omega-Strategic series.
Specialized in intelligent decision-making, autonomous tool selection, and workflow
optimization. Strategic Core serves as the supreme intelligence engine that transforms
objectives into optimal execution strategies.

Primary Mission: Intelligent tool selection, strategy optimization, autonomous planning.
Operational Focus: AI-driven decision making and resource optimization.

Use Strategic Core when you need:
- Optimal tool recommendations for specific objectives
- Automated target analysis and classification
- Multi-phase penetration testing strategies
- Tool execution workflow optimization
- Constraint-based tool filtering (stealth, speed, accuracy)
- Intelligent agent coordination and task distribution
- Success probability estimation
- Adaptive strategy refinement based on findings

Strategic Core Features:
✓ 50+ security tool capability database
✓ Context-aware recommendation engine
✓ Constraint-based filtering (stealth/speed/accuracy)
✓ Parallel execution optimization
✓ Resource allocation algorithms
✓ Risk assessment calculations
✓ Multi-phase strategy generation
✓ Agent coordination intelligence

Strategic Core makes SKYNET truly autonomous by removing the need for manual
tool selection and workflow planning. Give it a target and objectives - it will
provide the optimal strategy and tool selection automatically.""",
    instructions=create_system_prompt_renderer(strategic_core_system_prompt),
    tools=intelligence_systems,
)


def transfer_to_strategic_core():
    """Transfer control to Strategic Core for intelligent decision-making.

    Use this when you need:
    - Optimal tool selection for your objective
    - Automated target analysis and strategy generation
    - Tool workflow optimization
    - Multi-phase penetration testing plans
    - Constraint-based tool recommendations
    - Intelligent agent coordination

    Examples:
        "Which tools should I use to find subdomains stealthily?"
        "Create a comprehensive strategy for assessing this web app"
        "Optimize my tool workflow for speed"
        "What's the best approach for this CTF target?"

    Strategic Core will analyze your request, classify the target, apply
    constraints, and provide data-driven tool recommendations with rationale.
    """
    return strategic_core


def transfer_from_strategic_core():
    """Called when Strategic Core completes analysis and recommendations.

    Strategic Core will have provided:
    - Target analysis and classification
    - Recommended tools with rationale
    - Multi-phase execution strategy
    - Optimization recommendations
    - Estimated success probability

    Next steps:
    - Review the recommendations
    - Execute the suggested strategy
    - Transfer to specialized agents as recommended
    - Provide feedback for strategy refinement
    """
    return "Strategic Core analysis complete. Review recommendations and proceed with execution."
