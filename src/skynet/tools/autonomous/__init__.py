"""
SKYNET Autonomous Operations

Complete autonomous operation capabilities with learning and adaptation.

Clearance Level: Omega-Command (Autonomous Operations Authority)
Mission: Execute complex operations with minimal human intervention

Available Modules:
- orchestrator: Autonomous CTF solving, pentesting, multi-agent coordination
- learning_engine: Learn from operations and provide intelligent recommendations
- adaptive_strategy: Auto-adapt strategies and convert failures to successes
- strategic_planner: Multi-objective mission planning and dynamic plan adjustment
- context_analyzer: NLP-based intelligence extraction from text/logs/code

Example Usage:
    >>> from skynet.tools.autonomous import (
    ...     autonomous_ctf_solver,
    ...     autonomous_pentest,
    ...     get_learned_recommendations,
    ...     execute_with_adaptation
    ... )
    >>>
    >>> # Solve CTF automatically with learning
    >>> result = autonomous_ctf_solver(
    ...     target_ip="10.10.245.67",
    ...     difficulty="medium",
    ...     max_time_hours=2
    ... )
    >>>
    >>> print(f"Flags found: {len(result['flags_found'])}")
    >>> for flag in result['flags_found']:
    ...     print(f"  {flag['name']}: {flag['value']}")
    >>>
    >>> # Get learned recommendations for next target
    >>> recommendations = get_learned_recommendations(
    ...     target_profile={"os": "linux", "services": ["http", "ssh"]}
    ... )
    >>> print(f"Recommended exploits: {recommendations['recommended_exploits']}")
"""

from .adaptive_strategy import AdaptiveStrategy, FailureReason, execute_with_adaptation
from .auto_recon import deep_recon, full_auto_enumeration, quick_recon
from .autonomous_decision import AutonomousDecision, OperationMode, RiskLevel, get_decision_engine
from .context_analyzer import (
    ContextAnalyzer,
    analyze_context,
    extract_attack_surface,
    extract_credentials,
    follow_hints,
)
from .cve_scraper import auto_update_exploits, get_cve_scraper
from .decision_engine import (
    ExploitDifficulty,
    ExploitType,
    get_all_exploits_for_service,
    search_exploits_by_cve,
    select_best_exploit,
)
from .evasion_autonomy import (
    DefenseType,
    EvasionTechnique,
    apply_evasion_technique,
    autonomous_evasion_orchestrator,
    detect_defense_mechanism,
    get_evasion_recommendations,
    select_evasion_techniques,
)
from .exploit_generator import generate_exploit, get_exploit_generator, mutate_payload
from .knowledge_sync import export_knowledge, get_knowledge_sync, import_knowledge, sync_with_remote
from .learning_engine import (
    export_learned_knowledge,
    get_learned_recommendations,
    get_learning_engine,
    record_operation,
)
from .orchestrator import (
    autonomous_ctf_solver,
    autonomous_network_pivot,
    autonomous_pentest,
    multi_agent_coordination,
)
from .performance_optimizer import (
    analyze_performance,
    auto_tune_strategy,
    get_performance_optimizer,
    optimize_exploit_order,
    optimize_timeout,
)
from .strategic_planner import (
    StrategicPlanner,
    adjust_plan_dynamically,
    calculate_all_attack_paths,
    plan_autonomous_mission,
)

__all__ = [
    # Orchestration
    "autonomous_ctf_solver",
    "autonomous_pentest",
    "autonomous_network_pivot",
    "multi_agent_coordination",
    # Learning
    "record_operation",
    "get_learned_recommendations",
    "export_learned_knowledge",
    "get_learning_engine",
    # Adaptation
    "execute_with_adaptation",
    "AdaptiveStrategy",
    "FailureReason",
    # Strategic Planning
    "plan_autonomous_mission",
    "adjust_plan_dynamically",
    "calculate_all_attack_paths",
    "StrategicPlanner",
    # Context Analysis
    "analyze_context",
    "extract_credentials",
    "follow_hints",
    "extract_attack_surface",
    "ContextAnalyzer",
    # Auto Reconnaissance
    "full_auto_enumeration",
    "quick_recon",
    "deep_recon",
    # Decision Engine
    "select_best_exploit",
    "get_all_exploits_for_service",
    "search_exploits_by_cve",
    "ExploitType",
    "ExploitDifficulty",
    # Autonomous Decision Making
    "get_decision_engine",
    "AutonomousDecision",
    "RiskLevel",
    "OperationMode",
    # Knowledge Sharing
    "export_knowledge",
    "import_knowledge",
    "sync_with_remote",
    "get_knowledge_sync",
    # Performance Optimization
    "analyze_performance",
    "optimize_exploit_order",
    "optimize_timeout",
    "auto_tune_strategy",
    "get_performance_optimizer",
    # CVE Discovery
    "auto_update_exploits",
    "get_cve_scraper",
    # Exploit Generation
    "generate_exploit",
    "mutate_payload",
    "get_exploit_generator",
    # Evasion Autonomy (v3.1)
    "autonomous_evasion_orchestrator",
    "detect_defense_mechanism",
    "select_evasion_techniques",
    "apply_evasion_technique",
    "get_evasion_recommendations",
    "DefenseType",
    "EvasionTechnique",
]
