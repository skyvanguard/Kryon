"""
KRYON Decision Engine - Intelligent Tool Selection
===================================================

AI-driven decision engine that analyzes targets and automatically
selects optimal tools and strategies for cybersecurity operations.
"""

import json
import re
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

# Tool capability database
TOOL_CAPABILITIES = {
    # Network Scanning
    "nmap": {
        "category": "network_scan",
        "capabilities": ["port_scan", "service_detection", "os_detection", "script_scan"],
        "speed": "medium",
        "stealth": "medium",
        "accuracy": "high",
        "use_cases": ["initial_recon", "service_enum", "vulnerability_scan"],
    },
    "rustscan": {
        "category": "network_scan",
        "capabilities": ["fast_port_scan", "service_detection"],
        "speed": "very_high",
        "stealth": "low",
        "accuracy": "high",
        "use_cases": ["quick_recon", "ctf", "time_limited"],
    },
    "masscan": {
        "category": "network_scan",
        "capabilities": ["mass_port_scan", "large_scale"],
        "speed": "extreme",
        "stealth": "very_low",
        "accuracy": "medium",
        "use_cases": ["bulk_scan", "network_discovery", "internet_scale"],
    },
    # DNS/Subdomain
    "amass": {
        "category": "dns_enum",
        "capabilities": ["subdomain_enum", "asn_discovery", "passive_recon", "active_recon"],
        "speed": "medium",
        "stealth": "high",
        "accuracy": "very_high",
        "use_cases": ["subdomain_discovery", "asset_discovery", "passive_recon"],
    },
    "subfinder": {
        "category": "dns_enum",
        "capabilities": ["subdomain_enum", "passive_recon"],
        "speed": "high",
        "stealth": "very_high",
        "accuracy": "high",
        "use_cases": ["passive_recon", "quick_subdomain_discovery"],
    },
    "dnsenum": {
        "category": "dns_enum",
        "capabilities": ["dns_enum", "zone_transfer", "brute_force"],
        "speed": "medium",
        "stealth": "medium",
        "accuracy": "high",
        "use_cases": ["dns_recon", "zone_transfer_test"],
    },
    # Web Discovery
    "ffuf": {
        "category": "web_discovery",
        "capabilities": ["dir_brute", "file_discovery", "vhost_discovery", "parameter_fuzzing"],
        "speed": "very_high",
        "stealth": "low",
        "accuracy": "high",
        "use_cases": ["web_recon", "hidden_paths", "vhost_discovery"],
    },
    "gobuster": {
        "category": "web_discovery",
        "capabilities": ["dir_brute", "dns_brute", "vhost_discovery"],
        "speed": "high",
        "stealth": "low",
        "accuracy": "high",
        "use_cases": ["web_recon", "directory_discovery"],
    },
    "feroxbuster": {
        "category": "web_discovery",
        "capabilities": ["recursive_scan", "link_extraction", "auto_tune"],
        "speed": "very_high",
        "stealth": "low",
        "accuracy": "very_high",
        "use_cases": ["deep_web_scan", "comprehensive_discovery"],
    },
    # OSINT
    "theharvester": {
        "category": "osint",
        "capabilities": ["email_harvest", "subdomain_enum", "passive_recon", "social_engineering"],
        "speed": "medium",
        "stealth": "very_high",
        "accuracy": "high",
        "use_cases": ["passive_recon", "email_discovery", "social_engineering"],
    },
    "shodan": {
        "category": "osint",
        "capabilities": ["internet_scan", "service_discovery", "vulnerability_intel"],
        "speed": "high",
        "stealth": "very_high",
        "accuracy": "very_high",
        "use_cases": ["asset_discovery", "exposed_services", "vulnerability_intel"],
    },
    # Technology Detection
    "whatweb": {
        "category": "tech_detection",
        "capabilities": ["cms_detection", "framework_detection", "server_detection"],
        "speed": "high",
        "stealth": "variable",
        "accuracy": "very_high",
        "use_cases": ["tech_stack_analysis", "vulnerability_research"],
    },
    "wappalyzer": {
        "category": "tech_detection",
        "capabilities": ["tech_profiling", "recursive_crawl"],
        "speed": "medium",
        "stealth": "medium",
        "accuracy": "very_high",
        "use_cases": ["comprehensive_tech_analysis"],
    },
    # Vulnerability Scanning
    "nuclei": {
        "category": "vuln_scan",
        "capabilities": [
            "cve_detection",
            "misconfig_detection",
            "exposed_panels",
            "template_based",
        ],
        "speed": "very_high",
        "stealth": "low",
        "accuracy": "very_high",
        "use_cases": ["vuln_scan", "cve_detection", "security_audit"],
    },
    # SQL Injection
    "sqlmap": {
        "category": "injection",
        "capabilities": ["sqli_detection", "sqli_exploitation", "database_extraction"],
        "speed": "medium",
        "stealth": "very_low",
        "accuracy": "very_high",
        "use_cases": ["sqli_testing", "database_exploitation"],
    },
    # Exploitation
    "metasploit": {
        "category": "exploitation",
        "capabilities": ["exploit_execution", "payload_generation", "post_exploitation"],
        "speed": "medium",
        "stealth": "very_low",
        "accuracy": "high",
        "use_cases": ["exploitation", "payload_delivery", "post_exploit"],
    },
}


@function_tool
def analyze_target(
    target: str,
    target_type: str = "auto",
    scope: str = "comprehensive",
    stealth_level: str = "medium",
    time_constraint: str = "none",
    ctf=None,
) -> str:
    """
    Analyze target and recommend optimal reconnaissance strategy.

    Uses AI-driven decision engine to analyze the target and suggest
    the best tools and approach based on constraints and objectives.

    Args:
        target: Target URL, IP, domain, or network range
        target_type: Type of target (auto, web, network, api, mobile)
        scope: Scope of assessment (quick, standard, comprehensive, stealth)
        stealth_level: Required stealth (low, medium, high, very_high)
        time_constraint: Time limit (none, quick, medium, long)
        ctf: CTF context

    Returns:
        JSON string with analysis and recommendations

    Examples:
        # Auto-detect and analyze web application
        analyze_target(
            target="https://example.com",
            scope="comprehensive"
        )

        # Stealth network reconnaissance
        analyze_target(
            target="192.168.1.0/24",
            target_type="network",
            stealth_level="very_high"
        )

        # Quick CTF assessment
        analyze_target(
            target="10.10.10.5",
            scope="quick",
            time_constraint="quick"
        )
    """
    logger.info("analyze_target called target=%s target_type=%s scope=%s stealth=%s", target, target_type, scope, stealth_level)
    # Detect target type if auto
    if target_type == "auto":
        target_type = _detect_target_type(target)

    # Get recommended tools based on analysis
    recommended_tools = _get_recommended_tools(target_type, scope, stealth_level, time_constraint)

    # Create execution strategy
    strategy = _create_execution_strategy(target, target_type, recommended_tools, scope)

    analysis = {
        "target": target,
        "target_type": target_type,
        "scope": scope,
        "stealth_level": stealth_level,
        "recommended_tools": recommended_tools,
        "execution_strategy": strategy,
        "estimated_time": _estimate_time(strategy),
        "risk_level": _assess_risk(stealth_level, scope),
    }

    return json.dumps(analysis, indent=2)


@function_tool
def recommend_tools(
    objective: str,
    target_type: str = "web",
    constraints: str = "",
    priority: str = "accuracy",
    ctf=None,
) -> str:
    """
    Recommend optimal tools for specific objective.

    Args:
        objective: What you want to achieve (e.g., "find subdomains", "detect SQLi")
        target_type: Type of target (web, network, api, mobile)
        constraints: Constraints (e.g., "stealth required", "time limited")
        priority: Priority (speed, accuracy, stealth, comprehensive)
        ctf: CTF context

    Returns:
        JSON string with tool recommendations and rationale

    Examples:
        # Find hidden directories on web app
        recommend_tools(
            objective="discover hidden directories and files",
            target_type="web",
            priority="comprehensive"
        )

        # Stealthy subdomain enumeration
        recommend_tools(
            objective="enumerate subdomains",
            constraints="must be passive and stealthy",
            priority="stealth"
        )

        # Fast port scanning
        recommend_tools(
            objective="scan all ports quickly",
            target_type="network",
            priority="speed"
        )
    """
    logger.info("recommend_tools called objective=%s target_type=%s priority=%s", objective, target_type, priority)
    # Parse objective
    objective_keywords = _extract_keywords(objective.lower())

    # Match tools to objective
    matched_tools = _match_tools_to_objective(objective_keywords, target_type)

    # Filter by constraints
    if constraints:
        matched_tools = _apply_constraints(matched_tools, constraints)

    # Sort by priority
    matched_tools = _sort_by_priority(matched_tools, priority)

    recommendations = {
        "objective": objective,
        "target_type": target_type,
        "constraints": constraints,
        "priority": priority,
        "recommended_tools": matched_tools[:5],  # Top 5
        "alternative_tools": matched_tools[5:10],  # Next 5
        "reasoning": _generate_reasoning(objective_keywords, matched_tools[:5]),
    }

    return json.dumps(recommendations, indent=2)


@function_tool
def create_strategy(
    target: str,
    goals: str,
    available_time: str = "unlimited",
    stealth_required: bool = False,
    ctf=None,
) -> str:
    """
    Create comprehensive penetration testing strategy.

    Generates a multi-phase strategy with tool sequences and rationale.

    Args:
        target: Target to assess
        goals: Assessment goals (comma-separated)
        available_time: Available time (quick, medium, long, unlimited)
        stealth_required: Whether stealth is required
        ctf: CTF context

    Returns:
        JSON string with complete strategy

    Examples:
        # Comprehensive web app assessment
        create_strategy(
            target="https://example.com",
            goals="full security audit, find all vulnerabilities",
            available_time="long"
        )

        # Quick CTF strategy
        create_strategy(
            target="10.10.10.5",
            goals="get initial foothold, find user flag",
            available_time="quick"
        )

        # Stealth red team operation
        create_strategy(
            target="company.com",
            goals="enumerate attack surface, avoid detection",
            stealth_required=True
        )
    """
    logger.info("create_strategy called target=%s available_time=%s stealth=%s", target, available_time, stealth_required)
    goal_list = [g.strip() for g in goals.split(",")]

    # Build multi-phase strategy
    phases = _build_strategy_phases(target, goal_list, available_time, stealth_required)

    strategy = {
        "target": target,
        "goals": goal_list,
        "available_time": available_time,
        "stealth_required": stealth_required,
        "phases": phases,
        "total_estimated_time": _calculate_total_time(phases),
        "success_probability": _estimate_success_probability(phases),
        "recommendations": _generate_strategy_recommendations(phases),
    }

    return json.dumps(strategy, indent=2)


@function_tool
def optimize_workflow(tools: str, target: str, optimize_for: str = "speed", ctf=None) -> str:
    """
    Optimize tool execution workflow for efficiency.

    Args:
        tools: Comma-separated list of tools to use
        target: Target being assessed
        optimize_for: Optimization goal (speed, stealth, accuracy, coverage)
        ctf: CTF context

    Returns:
        JSON string with optimized workflow

    Examples:
        # Optimize for speed
        optimize_workflow(
            tools="nmap,gobuster,nuclei,sqlmap",
            target="https://example.com",
            optimize_for="speed"
        )

        # Optimize for stealth
        optimize_workflow(
            tools="amass,subfinder,theharvester",
            target="example.com",
            optimize_for="stealth"
        )
    """
    logger.info("optimize_workflow called tools=%s target=%s optimize_for=%s", tools, target, optimize_for)
    tool_list = [t.strip() for t in tools.split(",")]

    # Analyze dependencies and optimal order
    optimized_sequence = _optimize_tool_sequence(tool_list, target, optimize_for)

    # Identify parallelization opportunities
    parallel_groups = _identify_parallel_execution(optimized_sequence)

    # Calculate resource requirements
    resources = _calculate_resource_needs(tool_list)

    workflow = {
        "tools": tool_list,
        "target": target,
        "optimize_for": optimize_for,
        "optimized_sequence": optimized_sequence,
        "parallel_execution_groups": parallel_groups,
        "resource_requirements": resources,
        "estimated_time": _estimate_workflow_time(optimized_sequence, parallel_groups),
        "optimization_notes": _generate_optimization_notes(optimized_sequence, optimize_for),
    }

    return json.dumps(workflow, indent=2)


# Helper functions


def _detect_target_type(target: str) -> str:
    """Auto-detect target type from target string."""
    if target.startswith(("http://", "https://")):
        return "web"
    elif "/" in target or "-" in target:  # CIDR or range
        return "network"
    elif re.match(r"^\d+\.\d+\.\d+\.\d+$", target):  # IP
        return "host"
    elif "." in target and not target[0].isdigit():  # Domain
        return "domain"
    else:
        return "unknown"


def _get_recommended_tools(target_type: str, scope: str, stealth: str, time: str) -> list[dict[str, Any]]:
    """Get recommended tools based on parameters."""
    recommendations = []

    # Map target types to categories
    category_map = {
        "web": ["web_discovery", "tech_detection", "vuln_scan"],
        "network": ["network_scan", "service_enum"],
        "domain": ["dns_enum", "osint", "tech_detection"],
        "host": ["network_scan", "vuln_scan"],
    }

    categories = category_map.get(target_type, ["network_scan"])

    for tool_name, tool_info in TOOL_CAPABILITIES.items():
        if tool_info["category"] in categories:
            # Calculate suitability score
            score = _calculate_suitability_score(tool_info, scope, stealth, time)
            if score > 0.5:  # Threshold
                recommendations.append(
                    {
                        "tool": tool_name,
                        "category": tool_info["category"],
                        "score": score,
                        "reason": _generate_recommendation_reason(tool_info, scope, stealth, time),
                    }
                )

    # Sort by score
    recommendations.sort(key=lambda x: x["score"], reverse=True)
    return recommendations


def _calculate_suitability_score(tool_info: dict, scope: str, stealth: str, time: str) -> float:
    """Calculate how suitable a tool is for the given parameters."""
    score = 0.5  # Base score

    # Stealth matching
    stealth_map = {"very_high": 5, "high": 4, "medium": 3, "low": 2, "very_low": 1}
    required_stealth = stealth_map.get(stealth, 3)
    tool_stealth = stealth_map.get(tool_info["stealth"], 3)

    if tool_stealth >= required_stealth:
        score += 0.2
    else:
        score -= 0.1

    # Speed for time constraints
    if time == "quick" and tool_info["speed"] in ["high", "very_high", "extreme"]:
        score += 0.2

    # Accuracy for comprehensive scope
    if scope == "comprehensive" and tool_info["accuracy"] in ["high", "very_high"]:
        score += 0.15

    return min(score, 1.0)


def _generate_recommendation_reason(tool_info: dict, scope: str, stealth: str, time: str) -> str:
    """Generate human-readable reason for recommendation."""
    reasons = []

    if tool_info["accuracy"] in ["high", "very_high"]:
        reasons.append("high accuracy")

    if tool_info["speed"] in ["high", "very_high", "extreme"]:
        reasons.append("fast execution")

    if tool_info["stealth"] in ["high", "very_high"]:
        reasons.append("stealthy operation")

    if scope == "comprehensive" and len(tool_info["capabilities"]) > 3:
        reasons.append("comprehensive coverage")

    return "Recommended due to: " + ", ".join(reasons) if reasons else "Suitable for task"


def _create_execution_strategy(target: str, target_type: str, tools: list[dict], scope: str) -> dict:
    """Create execution strategy with phases."""
    return {
        "phase_1_reconnaissance": {
            "tools": [t["tool"] for t in tools if "recon" in str(t.get("category", ""))],
            "objective": "Initial reconnaissance and asset discovery",
        },
        "phase_2_enumeration": {
            "tools": [t["tool"] for t in tools if "enum" in str(t.get("category", ""))],
            "objective": "Service and technology enumeration",
        },
        "phase_3_vulnerability_scan": {
            "tools": [t["tool"] for t in tools if "vuln" in str(t.get("category", ""))],
            "objective": "Vulnerability identification",
        },
    }


def _estimate_time(strategy: dict) -> str:
    """Estimate total time for strategy."""
    phase_count = len(strategy)
    if phase_count <= 2:
        return "15-30 minutes"
    elif phase_count <= 3:
        return "30-60 minutes"
    else:
        return "1-3 hours"


def _assess_risk(stealth: str, scope: str) -> str:
    """Assess operational risk level."""
    if stealth == "very_high" or scope == "quick":
        return "low"
    elif stealth in ["high", "medium"] and scope == "standard":
        return "medium"
    else:
        return "high"


def _extract_keywords(text: str) -> list[str]:
    """Extract keywords from objective text."""
    keywords = []
    keyword_map = {
        "subdomain": ["subdomain", "domain enum", "dns enum"],
        "port": ["port", "scan", "service"],
        "directory": ["directory", "dir", "path", "file"],
        "vulnerability": ["vuln", "cve", "exploit", "security"],
        "sql": ["sql", "injection", "sqli", "database"],
        "technology": ["tech", "cms", "framework", "stack"],
    }

    for key, patterns in keyword_map.items():
        if any(p in text for p in patterns):
            keywords.append(key)

    return keywords


def _match_tools_to_objective(keywords: list[str], target_type: str) -> list[dict]:
    """Match tools to objective keywords."""
    matched = []

    for tool_name, tool_info in TOOL_CAPABILITIES.items():
        score = 0
        capabilities_str = " ".join(tool_info["capabilities"])

        for keyword in keywords:
            if keyword in capabilities_str or keyword in tool_info["category"]:
                score += 1

        if score > 0:
            matched.append(
                {
                    "tool": tool_name,
                    "score": score,
                    "capabilities": tool_info["capabilities"],
                    "category": tool_info["category"],
                }
            )

    matched.sort(key=lambda x: x["score"], reverse=True)
    return matched


def _apply_constraints(tools: list[dict], constraints: str) -> list[dict]:
    """Filter tools based on constraints."""
    constraints_lower = constraints.lower()

    filtered = []
    for tool in tools:
        tool_name = tool["tool"]
        tool_info = TOOL_CAPABILITIES.get(tool_name, {})

        # Check stealth constraint
        if "stealth" in constraints_lower or "passive" in constraints_lower:
            if tool_info.get("stealth") not in ["high", "very_high"]:
                continue

        # Check speed constraint
        if "fast" in constraints_lower or "quick" in constraints_lower:
            if tool_info.get("speed") not in ["high", "very_high", "extreme"]:
                continue

        filtered.append(tool)

    return filtered


def _sort_by_priority(tools: list[dict], priority: str) -> list[dict]:
    """Sort tools by priority criterion."""
    priority_map = {
        "speed": "speed",
        "accuracy": "accuracy",
        "stealth": "stealth",
        "comprehensive": "capabilities",
    }

    sort_key = priority_map.get(priority, "score")

    if sort_key == "capabilities":
        tools.sort(
            key=lambda x: len(TOOL_CAPABILITIES.get(x["tool"], {}).get("capabilities", [])),
            reverse=True,
        )
    else:
        # Already sorted by score in previous step
        pass

    return tools


def _generate_reasoning(keywords: list[str], tools: list[dict]) -> str:
    """Generate reasoning for tool selection."""
    if not tools:
        return "No suitable tools found for the specified objective."

    reasons = [
        f"Selected {len(tools)} tools based on objective keywords: {', '.join(keywords)}.",
        f"Top recommendation: {tools[0]['tool']} due to matching capabilities.",
        "Tools are ordered by relevance and suitability scores.",
    ]

    return " ".join(reasons)


def _build_strategy_phases(target: str, goals: list[str], time: str, stealth: bool) -> list[dict]:
    """Build multi-phase penetration testing strategy."""
    phases = [
        {
            "phase": 1,
            "name": "Reconnaissance",
            "objectives": ["Asset discovery", "Subdomain enumeration", "Technology detection"],
            "tools": ["amass", "subfinder", "whatweb"] if stealth else ["rustscan", "amass", "whatweb"],
            "duration": "Quick" if time == "quick" else "Medium",
        },
        {
            "phase": 2,
            "name": "Enumeration",
            "objectives": ["Service enumeration", "Directory discovery", "API discovery"],
            "tools": ["gobuster", "ffuf", "nuclei"],
            "duration": "Medium",
        },
    ]

    if "vulnerabilities" in " ".join(goals).lower():
        phases.append(
            {
                "phase": 3,
                "name": "Vulnerability Assessment",
                "objectives": ["CVE detection", "Misconfiguration discovery", "Injection testing"],
                "tools": ["nuclei", "sqlmap"],
                "duration": "Long",
            }
        )

    return phases


def _calculate_total_time(phases: list[dict]) -> str:
    """Calculate total estimated time."""
    return f"{len(phases) * 30}-{len(phases) * 60} minutes"


def _estimate_success_probability(phases: list[dict]) -> str:
    """Estimate success probability."""
    if len(phases) >= 3:
        return "High (75-90%)"
    elif len(phases) == 2:
        return "Medium (60-75%)"
    else:
        return "Low-Medium (40-60%)"


def _generate_strategy_recommendations(phases: list[dict]) -> list[str]:
    """Generate strategy recommendations."""
    return [
        "Execute phases sequentially for best results",
        "Review findings after each phase before proceeding",
        "Adjust tool parameters based on target responses",
        "Document all findings for correlation analysis",
    ]


def _optimize_tool_sequence(tools: list[str], target: str, optimize_for: str) -> list[str]:
    """Optimize tool execution sequence."""
    # Define logical dependencies
    order = []

    # Reconnaissance tools first
    recon_tools = [t for t in tools if t in ["amass", "subfinder", "dnsenum", "theharvester"]]
    order.extend(sorted(recon_tools))

    # Network scans
    network_tools = [t for t in tools if t in ["nmap", "rustscan", "masscan"]]
    order.extend(sorted(network_tools))

    # Web discovery
    web_tools = [t for t in tools if t in ["gobuster", "ffuf", "feroxbuster"]]
    order.extend(sorted(web_tools))

    # Vulnerability scanning
    vuln_tools = [t for t in tools if t in ["nuclei", "sqlmap", "nikto"]]
    order.extend(sorted(vuln_tools))

    # Add any remaining tools
    remaining = [t for t in tools if t not in order]
    order.extend(remaining)

    return order


def _identify_parallel_execution(sequence: list[str]) -> list[list[str]]:
    """Identify tools that can run in parallel."""
    parallel_groups = []

    # Group passive tools together
    passive_tools = ["amass", "subfinder", "theharvester", "shodan"]
    passive_group = [t for t in sequence if t in passive_tools]
    if len(passive_group) > 1:
        parallel_groups.append(passive_group)

    # Group web discovery tools
    web_discovery = ["gobuster", "ffuf", "feroxbuster"]
    web_group = [t for t in sequence if t in web_discovery]
    if len(web_group) > 1:
        parallel_groups.append(web_group)

    return parallel_groups


def _calculate_resource_needs(tools: list[str]) -> dict:
    """Calculate resource requirements."""
    return {
        "cpu_intensive": [t for t in tools if t in ["masscan", "rustscan", "nuclei"]],
        "network_intensive": [t for t in tools if t in ["nmap", "gobuster", "ffuf"]],
        "api_required": [t for t in tools if t in ["shodan", "amass"]],
        "wordlist_required": [t for t in tools if t in ["gobuster", "ffuf", "feroxbuster"]],
    }


def _estimate_workflow_time(sequence: list[str], parallel_groups: list[list[str]]) -> str:
    """Estimate total workflow time."""
    # Rough estimation
    total_mins = len(sequence) * 10  # 10 mins per tool average
    parallel_savings = sum(len(g) - 1 for g in parallel_groups) * 10  # Save time on parallel
    estimated = max(total_mins - parallel_savings, len(sequence))

    if estimated < 30:
        return "15-30 minutes"
    elif estimated < 60:
        return "30-60 minutes"
    elif estimated < 120:
        return "1-2 hours"
    else:
        return f"{estimated // 60}-{(estimated // 60) + 1} hours"


def _generate_optimization_notes(sequence: list[str], optimize_for: str) -> list[str]:
    """Generate optimization notes."""
    notes = [
        f"Sequence optimized for: {optimize_for}",
        f"Total tools in workflow: {len(sequence)}",
        "Tools are ordered by logical dependencies",
        "Parallel execution opportunities identified where safe",
    ]

    if optimize_for == "speed":
        notes.append("Consider using fast tools like rustscan and ffuf")
    elif optimize_for == "stealth":
        notes.append("Passive tools prioritized to minimize detection")
    elif optimize_for == "accuracy":
        notes.append("Comprehensive tools selected for thorough coverage")

    return notes
