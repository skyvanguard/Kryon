"""
KRYON Framework - Intelligence & Decision Engine Module
========================================================

Intelligent decision-making and strategic planning for autonomous
cybersecurity operations.

Components:
- Decision Engine: Automatic tool selection and strategy planning
- Context Analyzer: Target analysis and environment assessment
- Tool Recommender: AI-driven tool recommendation
- Strategy Planner: Multi-stage attack planning
- Correlation Engine: Vulnerability correlation and chaining
"""

from .context_analyzer import analyze_context, assess_security, classify_target, detect_technology
from .decision_engine import analyze_target, create_strategy, optimize_workflow, recommend_tools
from .vulnerability_correlator import (
    correlate_vulnerabilities,
    find_attack_chains,
    generate_exploit_path,
    prioritize_findings,
)

__all__ = [
    # Decision Engine
    "analyze_target",
    "recommend_tools",
    "create_strategy",
    "optimize_workflow",
    # Context Analyzer
    "analyze_context",
    "classify_target",
    "detect_technology",
    "assess_security",
    # Vulnerability Correlator
    "correlate_vulnerabilities",
    "find_attack_chains",
    "prioritize_findings",
    "generate_exploit_path",
]
