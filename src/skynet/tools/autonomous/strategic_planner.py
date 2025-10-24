"""
SKYNET Strategic Planner - Autonomous Mission Planning
======================================================

Advanced strategic planning system that generates multi-objective attack plans,
calculates multiple attack paths, and dynamically adjusts strategies during execution.

Clearance Level: Omega-Strategic (Strategic Planning Authority)
Classification: RESTRICTED
Mission: Plan and execute complex multi-stage operations autonomously

Features:
- Multi-objective mission planning
- Multiple attack path calculation
- Dynamic plan adjustment during execution
- Resource optimization and allocation
- Dependency analysis and task ordering
- Probability-based success estimation
"""

import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional


class StrategicPlanner:
    """
    Strategic planning engine for autonomous operations.

    Plans complex missions with:
    - Multiple objectives (e.g., initial_access + privilege_escalation + persistence)
    - Resource constraints (time, agents, tools)
    - Multiple attack paths with fallbacks
    - Dynamic replanning during execution
    """

    def __init__(self):
        """Initialize strategic planner."""
        self.attack_path_database = self._build_attack_path_database()
        self.objective_dependencies = self._build_objective_dependencies()
        # Performance optimization: cache topological sorts
        self._topo_sort_cache = {}

    def _build_attack_path_database(self) -> Dict[str, list[dict]]:
        """
        Build database of known attack paths.

        Returns:
            Dictionary mapping objectives to possible attack paths
        """
        return {
            "initial_access": [
                {
                    "path_id": "web_exploit",
                    "steps": ["port_scan", "web_enum", "vuln_scan", "exploit_web"],
                    "required_tools": ["nmap", "gobuster", "nuclei", "metasploit"],
                    "estimated_time": 600,  # 10 minutes
                    "success_probability": 0.75,
                    "stealth_level": "medium",
                    "complexity": "medium",
                },
                {
                    "path_id": "ssh_bruteforce",
                    "steps": ["port_scan", "ssh_enum", "credential_spray"],
                    "required_tools": ["nmap", "hydra"],
                    "estimated_time": 900,  # 15 minutes
                    "success_probability": 0.50,
                    "stealth_level": "low",
                    "complexity": "low",
                },
                {
                    "path_id": "service_exploit",
                    "steps": ["port_scan", "service_enum", "exploit_search", "exploit_execution"],
                    "required_tools": ["nmap", "searchsploit", "metasploit"],
                    "estimated_time": 750,  # 12.5 minutes
                    "success_probability": 0.65,
                    "stealth_level": "medium",
                    "complexity": "medium",
                },
            ],
            "privilege_escalation": [
                {
                    "path_id": "linux_privesc_automated",
                    "steps": ["enum_system", "run_linpeas", "exploit_suid", "get_root"],
                    "required_tools": ["linpeas", "gtfobins"],
                    "estimated_time": 300,  # 5 minutes
                    "success_probability": 0.80,
                    "stealth_level": "medium",
                    "complexity": "low",
                },
                {
                    "path_id": "windows_privesc_automated",
                    "steps": ["enum_system", "run_winpeas", "exploit_token", "get_system"],
                    "required_tools": ["winpeas", "powerup"],
                    "estimated_time": 450,  # 7.5 minutes
                    "success_probability": 0.70,
                    "stealth_level": "medium",
                    "complexity": "medium",
                },
                {
                    "path_id": "kernel_exploit",
                    "steps": ["enum_kernel", "find_exploit", "compile_exploit", "execute"],
                    "required_tools": ["linux-exploit-suggester"],
                    "estimated_time": 600,  # 10 minutes
                    "success_probability": 0.60,
                    "stealth_level": "low",
                    "complexity": "high",
                },
            ],
            "persistence": [
                {
                    "path_id": "ssh_key_persistence",
                    "steps": ["gen_ssh_key", "add_authorized_keys", "test_connection"],
                    "required_tools": ["ssh-keygen"],
                    "estimated_time": 120,  # 2 minutes
                    "success_probability": 0.90,
                    "stealth_level": "high",
                    "complexity": "low",
                },
                {
                    "path_id": "cron_persistence",
                    "steps": ["create_reverse_shell", "add_cron_job", "verify"],
                    "required_tools": ["cron"],
                    "estimated_time": 180,  # 3 minutes
                    "success_probability": 0.85,
                    "stealth_level": "medium",
                    "complexity": "low",
                },
            ],
            "data_exfiltration": [
                {
                    "path_id": "find_and_exfil_flags",
                    "steps": ["search_flags", "read_flags", "exfiltrate"],
                    "required_tools": ["find", "grep"],
                    "estimated_time": 180,  # 3 minutes
                    "success_probability": 0.95,
                    "stealth_level": "high",
                    "complexity": "low",
                },
                {
                    "path_id": "database_dump",
                    "steps": ["enum_databases", "dump_data", "compress", "transfer"],
                    "required_tools": ["mysqldump", "tar"],
                    "estimated_time": 600,  # 10 minutes
                    "success_probability": 0.75,
                    "stealth_level": "low",
                    "complexity": "medium",
                },
            ],
            # Alias for backward compatibility
            "exfiltrate_data": [
                {
                    "path_id": "find_and_exfil_flags",
                    "steps": ["search_flags", "read_flags", "exfiltrate"],
                    "required_tools": ["find", "grep"],
                    "estimated_time": 180,  # 3 minutes
                    "success_probability": 0.95,
                    "stealth_level": "high",
                    "complexity": "low",
                },
                {
                    "path_id": "database_dump",
                    "steps": ["enum_databases", "dump_data", "compress", "transfer"],
                    "required_tools": ["mysqldump", "tar"],
                    "estimated_time": 600,  # 10 minutes
                    "success_probability": 0.75,
                    "stealth_level": "low",
                    "complexity": "medium",
                },
            ],
            "lateral_movement": [
                {
                    "path_id": "network_pivot",
                    "steps": ["enum_network", "find_targets", "lateral_exploit"],
                    "required_tools": ["nmap", "chisel", "metasploit"],
                    "estimated_time": 900,  # 15 minutes
                    "success_probability": 0.65,
                    "stealth_level": "low",
                    "complexity": "high",
                },
            ],
            "establish_persistence": [
                {
                    "path_id": "backdoor_creation",
                    "steps": ["create_backdoor", "install_persistence", "verify"],
                    "required_tools": ["msfvenom", "systemd"],
                    "estimated_time": 300,  # 5 minutes
                    "success_probability": 0.85,
                    "stealth_level": "medium",
                    "complexity": "medium",
                },
            ],
        }

    def _build_objective_dependencies(self) -> Dict[str, list[str]]:
        """
        Build dependency graph of objectives.

        Returns:
            Dictionary mapping objectives to their dependencies
        """
        return {
            "initial_access": [],  # No dependencies
            "privilege_escalation": ["initial_access"],  # Needs initial access first
            "persistence": ["initial_access"],  # Needs at least user access
            "data_exfiltration": ["initial_access"],  # Needs access to system
            "exfiltrate_data": ["privilege_escalation"],  # Alias - needs elevated access
            "lateral_movement": ["privilege_escalation"],  # Needs elevated privileges
            "establish_persistence": ["initial_access"],  # Alias for persistence
            "domain_admin": ["initial_access", "privilege_escalation"],  # Needs root/system
        }

    def autonomous_mission_planner(
        self,
        target_network: str,
        objectives: list[str],
        constraints: Optional[dict[str, Any]] = None,
        resources: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Generate comprehensive mission plan with multiple objectives.

        Args:
            target_network: Target IP or network
            objectives: List of objectives (e.g., ["initial_access", "privilege_escalation"])
            constraints: Constraints dict (time_limit, stealth_level, noise_tolerance)
            resources: Available resources (agents, tools, budget)

        Returns:
            Dictionary with comprehensive mission plan
        """
        constraints = constraints or {}
        resources = resources or {}

        # Validate and order objectives by dependencies
        ordered_objectives = self._order_objectives_by_dependencies(objectives)

        # Generate multiple plans
        plans = []
        for i in range(3):  # Generate 3 alternative plans
            plan = self._generate_single_plan(
                target_network, ordered_objectives, constraints, resources, plan_variant=i
            )
            plans.append(plan)

        # Rank plans by success probability and time
        ranked_plans = self._rank_plans(plans, constraints)

        # Select primary and backup plans
        primary_plan = ranked_plans[0]
        contingency_plans = ranked_plans[1:3]

        result = {
            "target_network": target_network,
            "objectives": objectives,
            "ordered_objectives": ordered_objectives,
            "primary_plan": primary_plan,
            "contingency_plans": contingency_plans,
            "estimated_total_time": primary_plan["estimated_time"],
            "estimated_success_probability": primary_plan["success_probability"],
            "resource_requirements": primary_plan["resources_required"],
            "critical_dependencies": self._identify_critical_dependencies(primary_plan),
            "risk_assessment": self._assess_risks(primary_plan, constraints),
            "plan_metadata": {
                "generated_at": datetime.now().isoformat(),
                "planner_version": "1.0.0",
                "total_plans_generated": len(plans),
            },
        }

        return result

    def _order_objectives_by_dependencies(self, objectives: list[str]) -> list[str]:
        """
        Order objectives based on dependencies using topological sort.

        Performance: Uses cached results for repeated objective sets.

        Args:
            objectives: List of objective names

        Returns:
            Ordered list of objectives
        """
        # Performance optimization: check cache first
        cache_key = tuple(sorted(objectives))
        if cache_key in self._topo_sort_cache:
            return self._topo_sort_cache[cache_key]

        # Build dependency graph for requested objectives
        graph = {obj: [] for obj in objectives}
        in_degree = {obj: 0 for obj in objectives}

        for obj in objectives:
            deps = self.objective_dependencies.get(obj, [])
            for dep in deps:
                if dep in objectives:  # Only consider deps that are in our objectives
                    graph[dep].append(obj)
                    in_degree[obj] += 1

        # Topological sort (Kahn's algorithm)
        queue = [obj for obj in objectives if in_degree[obj] == 0]
        ordered = []

        while queue:
            node = queue.pop(0)
            ordered.append(node)

            for neighbor in graph[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        # If cycle detected, return original order
        if len(ordered) != len(objectives):
            result = objectives
        else:
            result = ordered

        # Cache result for future use
        self._topo_sort_cache[cache_key] = result
        return result

    def _generate_single_plan(
        self,
        target_network: str,
        objectives: list[str],
        constraints: dict[str, Any],
        resources: dict[str, Any],
        plan_variant: int = 0,
    ) -> dict[str, Any]:
        """
        Generate a single plan variant.

        Args:
            target_network: Target network
            objectives: Ordered list of objectives
            constraints: Operation constraints
            resources: Available resources
            plan_variant: Variant number (0, 1, 2 for different approaches)

        Returns:
            Complete plan dictionary
        """
        plan = {
            "plan_id": f"plan_{plan_variant}_{int(time.time())}",
            "variant": plan_variant,
            "stages": [],
            "estimated_time": 0,
            "success_probability": 1.0,
            "resources_required": defaultdict(set),
            "stealth_score": 0.0,
        }

        time_budget = constraints.get("time_limit", float("inf"))
        stealth_requirement = constraints.get("stealth_level", "medium")

        for objective in objectives:
            # Get possible attack paths for this objective
            paths = self.attack_path_database.get(objective, [])

            if not paths:
                # Unknown objective, create generic path
                paths = [
                    {
                        "path_id": f"generic_{objective}",
                        "steps": [objective],
                        "required_tools": [],
                        "estimated_time": 300,
                        "success_probability": 0.50,
                        "stealth_level": "medium",
                        "complexity": "unknown",
                    }
                ]

            # Select path based on variant
            if plan_variant == 0:
                # Variant 0: Highest success probability
                selected_path = max(paths, key=lambda p: p["success_probability"])
            elif plan_variant == 1:
                # Variant 1: Fastest path
                selected_path = min(paths, key=lambda p: p["estimated_time"])
            else:
                # Variant 2: Most stealthy
                stealth_scores = {"low": 1, "medium": 2, "high": 3, "very_high": 4}
                selected_path = max(paths, key=lambda p: stealth_scores.get(p["stealth_level"], 2))

            # Add stage to plan
            stage = {
                "objective": objective,
                "path": selected_path,
                "estimated_time": selected_path["estimated_time"],
                "success_probability": selected_path["success_probability"],
                "steps": selected_path["steps"],
                "required_tools": selected_path["required_tools"],
            }

            plan["stages"].append(stage)
            plan["estimated_time"] += selected_path["estimated_time"]
            plan["success_probability"] *= selected_path["success_probability"]

            for tool in selected_path["required_tools"]:
                plan["resources_required"]["tools"].add(tool)

        # Calculate stealth score (average across stages)
        stealth_scores = {"low": 1, "medium": 2, "high": 3, "very_high": 4}
        avg_stealth = sum(
            stealth_scores.get(s["path"]["stealth_level"], 2) for s in plan["stages"]
        ) / len(plan["stages"])
        plan["stealth_score"] = avg_stealth

        # Convert sets to lists for JSON serialization
        plan["resources_required"] = {k: list(v) for k, v in plan["resources_required"].items()}

        return plan

    def _rank_plans(self, plans: list[dict], constraints: dict[str, Any]) -> list[dict]:
        """
        Rank plans by composite score considering multiple factors.

        Args:
            plans: List of plan dictionaries
            constraints: Operation constraints

        Returns:
            Ranked list of plans (best first)
        """

        def calculate_score(plan: Dict) -> float:
            # Composite score based on multiple factors
            success_weight = 0.4
            time_weight = 0.3
            stealth_weight = 0.2
            complexity_weight = 0.1

            # Success probability (higher is better)
            success_score = plan["success_probability"]

            # Time score (faster is better, normalize to 0-1)
            max_time = max(p["estimated_time"] for p in plans)
            time_score = 1.0 - (plan["estimated_time"] / max_time) if max_time > 0 else 1.0

            # Stealth score (already normalized 0-4, convert to 0-1)
            stealth_score = plan["stealth_score"] / 4.0

            # Complexity score (simpler is better)
            complexity_score = 1.0 - (len(plan["stages"]) / 10.0)  # Assume max 10 stages

            # Apply stealth constraint if specified
            if constraints.get("stealth_level") == "high":
                stealth_weight = 0.4
                success_weight = 0.3

            total_score = (
                success_score * success_weight
                + time_score * time_weight
                + stealth_score * stealth_weight
                + complexity_score * complexity_weight
            )

            return total_score

        # Add scores to plans
        for plan in plans:
            plan["composite_score"] = calculate_score(plan)

        # Sort by score (descending)
        return sorted(plans, key=lambda p: p["composite_score"], reverse=True)

    def _identify_critical_dependencies(self, plan: Dict) -> list[dict]:
        """
        Identify critical dependencies in the plan.

        Args:
            plan: Plan dictionary

        Returns:
            List of critical dependencies
        """
        dependencies = []

        for i, stage in enumerate(plan["stages"]):
            if i > 0:
                dependency = {
                    "stage": i,
                    "depends_on": i - 1,
                    "description": f"{stage['objective']} requires {plan['stages'][i - 1]['objective']}",
                    "criticality": "high" if stage["success_probability"] < 0.7 else "medium",
                }
                dependencies.append(dependency)

        return dependencies

    def _assess_risks(self, plan: Dict, constraints: dict[str, Any]) -> dict[str, Any]:
        """
        Assess risks associated with the plan.

        Args:
            plan: Plan dictionary
            constraints: Operation constraints

        Returns:
            Risk assessment dictionary
        """
        risks = {"overall_risk": "medium", "risk_factors": [], "mitigation_strategies": []}

        # Time risk
        if plan["estimated_time"] > constraints.get("time_limit", float("inf")):
            risks["risk_factors"].append(
                {
                    "type": "time_overrun",
                    "severity": "high",
                    "description": "Estimated time exceeds constraint",
                }
            )
            risks["mitigation_strategies"].append("Use faster attack paths")

        # Success risk
        if plan["success_probability"] < 0.6:
            risks["risk_factors"].append(
                {
                    "type": "low_success_probability",
                    "severity": "high",
                    "description": f"Success probability only {plan['success_probability']:.1%}",
                }
            )
            risks["mitigation_strategies"].append("Prepare multiple backup plans")

        # Stealth risk
        if plan["stealth_score"] < 2.0 and constraints.get("stealth_level") == "high":
            risks["risk_factors"].append(
                {
                    "type": "low_stealth",
                    "severity": "medium",
                    "description": "Plan may be too noisy for stealth requirement",
                }
            )
            risks["mitigation_strategies"].append("Use more passive techniques")

        # Determine overall risk
        high_severity_count = sum(1 for r in risks["risk_factors"] if r["severity"] == "high")
        if high_severity_count >= 2:
            risks["overall_risk"] = "high"
        elif high_severity_count == 1:
            risks["overall_risk"] = "medium"
        else:
            risks["overall_risk"] = "low"

        return risks

    def dynamic_plan_adjustment(
        self,
        current_plan: dict[str, Any],
        current_progress: dict[str, Any],
        new_discoveries: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Dynamically adjust plan based on current progress and new discoveries.

        Args:
            current_plan: Original plan
            current_progress: Current execution status
            new_discoveries: New information discovered during execution

        Returns:
            Adjusted plan dictionary
        """
        new_discoveries = new_discoveries or {}

        adjustments = {
            "plan_adjusted": False,
            "adjustments_made": [],
            "new_plan": current_plan.copy(),
            "adjustment_reason": [],
        }

        completed_stages = current_progress.get("completed_stages", [])
        current_stage_idx = len(completed_stages)

        # Check if we're behind schedule
        elapsed_time = current_progress.get("elapsed_time", 0)
        expected_time = sum(
            current_plan["stages"][i]["estimated_time"] for i in range(current_stage_idx)
        )

        if elapsed_time > expected_time * 1.5:
            # We're significantly behind schedule
            adjustments["plan_adjusted"] = True
            adjustments["adjustment_reason"].append("behind_schedule")
            adjustments["adjustments_made"].append(
                {
                    "type": "prioritization",
                    "action": "Skip non-critical stages and focus on primary objective",
                }
            )

        # Check for new critical vulnerabilities
        if new_discoveries.get("critical_vulnerability"):
            vuln = new_discoveries["critical_vulnerability"]
            adjustments["plan_adjusted"] = True
            adjustments["adjustment_reason"].append("critical_vulnerability_found")
            adjustments["adjustments_made"].append(
                {
                    "type": "opportunity",
                    "action": f"Exploit {vuln['name']} immediately (higher success probability)",
                }
            )

            # Add new stage at beginning of remaining stages
            new_stage = {
                "objective": "exploit_critical_vuln",
                "path": {
                    "path_id": "critical_exploit",
                    "steps": ["exploit_vulnerability"],
                    "estimated_time": 300,
                    "success_probability": 0.90,
                },
                "estimated_time": 300,
                "success_probability": 0.90,
                "steps": ["exploit_vulnerability"],
            }

            # Insert after current stage
            adjustments["new_plan"]["stages"].insert(current_stage_idx, new_stage)

        # Check if encountering too many failures
        failure_count = current_progress.get("failures", 0)
        if failure_count >= 3:
            adjustments["plan_adjusted"] = True
            adjustments["adjustment_reason"].append("multiple_failures")
            adjustments["adjustments_made"].append(
                {"type": "fallback", "action": "Switch to contingency plan (backup strategy)"}
            )

        # Check if time is running out
        time_remaining = current_progress.get("time_limit", float("inf")) - elapsed_time
        estimated_remaining = sum(
            current_plan["stages"][i]["estimated_time"]
            for i in range(current_stage_idx, len(current_plan["stages"]))
        )

        if estimated_remaining > time_remaining:
            adjustments["plan_adjusted"] = True
            adjustments["adjustment_reason"].append("time_constraint")
            adjustments["adjustments_made"].append(
                {"type": "acceleration", "action": "Use faster (but less stealthy) techniques"}
            )

            # Replace remaining stages with faster alternatives
            for i in range(current_stage_idx, len(adjustments["new_plan"]["stages"])):
                stage = adjustments["new_plan"]["stages"][i]
                objective = stage["objective"]
                paths = self.attack_path_database.get(objective, [])

                if paths:
                    # Select fastest path
                    fastest_path = min(paths, key=lambda p: p["estimated_time"])
                    adjustments["new_plan"]["stages"][i]["path"] = fastest_path
                    adjustments["new_plan"]["stages"][i]["estimated_time"] = fastest_path[
                        "estimated_time"
                    ]

        return adjustments

    def calculate_attack_paths(
        self, target_profile: dict[str, Any], vulnerabilities: List[dict[str, Any]]
    ) -> List[dict[str, Any]]:
        """
        Calculate all possible attack paths based on target profile and vulnerabilities.

        Args:
            target_profile: Target characteristics (os, services, versions)
            vulnerabilities: List of identified vulnerabilities

        Returns:
            List of possible attack paths ordered by success probability
        """
        paths = []

        target_os = target_profile.get("os", "unknown")
        services = target_profile.get("services", [])

        # Generate paths based on vulnerabilities
        for vuln in vulnerabilities:
            path = {
                "path_id": f"vuln_{vuln.get('id', 'unknown')}",
                "type": "vulnerability_exploit",
                "entry_point": vuln.get("service", "unknown"),
                "steps": [
                    "verify_vulnerability",
                    "prepare_exploit",
                    "execute_exploit",
                    "establish_access",
                ],
                "estimated_time": self._estimate_exploit_time(vuln),
                "success_probability": self._estimate_success_probability(vuln, target_profile),
                "required_tools": self._determine_required_tools(vuln),
                "privilege_gained": vuln.get("privilege_level", "user"),
                "stealth_level": self._assess_stealth_level(vuln),
                "complexity": vuln.get("complexity", "medium"),
            }
            paths.append(path)

        # Generate service-based paths
        for service in services:
            service_paths = self._generate_service_paths(service, target_os)
            paths.extend(service_paths)

        # Deduplicate and rank paths
        unique_paths = self._deduplicate_paths(paths)
        ranked_paths = sorted(unique_paths, key=lambda p: p["success_probability"], reverse=True)

        return ranked_paths

    def _estimate_exploit_time(self, vuln: Dict) -> int:
        """Estimate time to exploit a vulnerability (in seconds)."""
        complexity_time = {
            "low": 300,  # 5 minutes
            "medium": 600,  # 10 minutes
            "high": 1200,  # 20 minutes
        }
        return complexity_time.get(vuln.get("complexity", "medium"), 600)

    def _estimate_success_probability(self, vuln: Dict, target_profile: Dict) -> float:
        """Estimate success probability for exploiting a vulnerability."""
        base_prob = {"critical": 0.85, "high": 0.70, "medium": 0.55, "low": 0.40}.get(
            vuln.get("severity", "medium"), 0.50
        )

        # Adjust based on CVE/exploit availability
        if vuln.get("has_public_exploit"):
            base_prob += 0.15

        # Adjust based on target configuration
        if vuln.get("requires_auth") and not target_profile.get("credentials_available"):
            base_prob -= 0.20

        return min(0.95, max(0.10, base_prob))

    def _determine_required_tools(self, vuln: Dict) -> list[str]:
        """Determine tools required for exploiting vulnerability."""
        tools = []

        exploit_type = vuln.get("type", "").lower()

        if "sql" in exploit_type:
            tools.append("sqlmap")
        elif "xss" in exploit_type or "injection" in exploit_type:
            tools.extend(["burp", "ffuf"])
        elif "buffer" in exploit_type or "overflow" in exploit_type:
            tools.append("metasploit")
        elif "file" in exploit_type:
            tools.append("gobuster")

        return tools or ["metasploit"]  # Default to metasploit

    def _assess_stealth_level(self, vuln: Dict) -> str:
        """Assess stealth level of exploiting a vulnerability."""
        if vuln.get("requires_bruteforce"):
            return "low"
        elif vuln.get("type") == "sqli":
            return "medium"
        elif vuln.get("type") in ["lfi", "rfi"]:
            return "medium"
        else:
            return "high"

    def _generate_service_paths(self, service: Dict, target_os: str) -> list[dict]:
        """Generate attack paths for a specific service."""
        paths = []

        service_name = service.get("name", "").lower()

        # SSH paths
        if "ssh" in service_name:
            paths.append(
                {
                    "path_id": "ssh_credential_attack",
                    "type": "credential_attack",
                    "entry_point": "ssh",
                    "steps": ["enum_users", "credential_spray", "ssh_login"],
                    "estimated_time": 900,
                    "success_probability": 0.45,
                    "required_tools": ["hydra", "medusa"],
                    "privilege_gained": "user",
                    "stealth_level": "low",
                    "complexity": "low",
                }
            )

        # HTTP/HTTPS paths
        if "http" in service_name:
            paths.append(
                {
                    "path_id": "web_application_attack",
                    "type": "web_exploit",
                    "entry_point": "http",
                    "steps": ["dir_enum", "vuln_scan", "exploit"],
                    "estimated_time": 600,
                    "success_probability": 0.70,
                    "required_tools": ["gobuster", "nuclei", "sqlmap"],
                    "privilege_gained": "www-data",
                    "stealth_level": "medium",
                    "complexity": "medium",
                }
            )

        return paths

    def _deduplicate_paths(self, paths: list[dict]) -> list[dict]:
        """Remove duplicate paths."""
        seen = set()
        unique_paths = []

        for path in paths:
            # Create unique identifier
            identifier = (path["type"], path["entry_point"], tuple(path["steps"]))

            if identifier not in seen:
                seen.add(identifier)
                unique_paths.append(path)

        return unique_paths


# Convenience functions
def plan_autonomous_mission(
    target_network: str,
    objectives: list[str],
    constraints: Optional[dict[str, Any]] = None,
    resources: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Plan autonomous mission with strategic planner.

    Args:
        target_network: Target IP or network
        objectives: Mission objectives
        constraints: Operation constraints
        resources: Available resources

    Returns:
        Comprehensive mission plan
    """
    planner = StrategicPlanner()
    return planner.autonomous_mission_planner(target_network, objectives, constraints, resources)


def adjust_plan_dynamically(
    current_plan: dict[str, Any],
    current_progress: dict[str, Any],
    new_discoveries: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Adjust plan based on current execution state.

    Args:
        current_plan: Original plan
        current_progress: Current progress
        new_discoveries: New information

    Returns:
        Adjusted plan
    """
    planner = StrategicPlanner()
    return planner.dynamic_plan_adjustment(current_plan, current_progress, new_discoveries)


def calculate_all_attack_paths(
    target_profile: dict[str, Any], vulnerabilities: List[dict[str, Any]]
) -> List[dict[str, Any]]:
    """
    Calculate all possible attack paths for target.

    Args:
        target_profile: Target characteristics
        vulnerabilities: Identified vulnerabilities

    Returns:
        List of attack paths
    """
    planner = StrategicPlanner()
    return planner.calculate_attack_paths(target_profile, vulnerabilities)
