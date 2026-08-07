"""
KRYON Autonomous Operations - Orchestrator

Multi-agent autonomous orchestration and coordination.

Clearance Level: Omega-Command (Autonomous Operations Authority)
Specialization: Autonomous decision-making and multi-stage operations
Mission: Execute complex operations with minimal human intervention

This module provides:
- Autonomous CTF solving
- Autonomous penetration testing
- Multi-agent coordination
- Adaptive strategy execution
- End-to-end operation automation
"""

import json
import logging
import os
import time
from datetime import datetime
from typing import Any

from kryon.sdk.agents import function_tool

logger = logging.getLogger(__name__)

# Per-host wall budget ceiling for the autonomous pentest (seconds). Each host
# gets min(this, remaining_budget / hosts_left) so a wide sweep can't spend the
# whole engagement on the first box.
_MAX_PER_HOST_SECONDS = 3600.0


# Helpers extraídos a módulos hermanos (F-split — orchestrator.py era 1612 líneas).
# Re-exportados para que `from ...orchestrator import X` siga funcionando.
from kryon.tools.autonomous._exploit import (  # noqa: F401
    _autonomous_flag_hunting,
    _autonomous_privilege_escalation,
    _msf_exploit,
    execute_exploit_autonomous,
)
from kryon.tools.autonomous._pivot import (  # noqa: F401
    _as_private_network,
    _autonomous_compromise_through_pivot,
    _check_lateral_movement,
    _check_objective_achieved,
    _default_pivot_runner,
    _default_proxied_scanner,
    _discover_internal_networks,
    _enumerate_through_pivot,
    _networks_from_text,
    _parse_nmap_hosts,
    _private_24_from_ip,
)
from kryon.tools.autonomous._reports import (  # noqa: F401
    _generate_autonomous_report,
    _generate_pentest_report,
)


@function_tool(strict_mode=False)
def autonomous_ctf_solver(
    target_ip: str,
    target_type: str = "auto",
    difficulty: str = "medium",
    max_time_hours: int = 2,
    flags_needed: list[str] | None = None,
    output_report: str = "/tmp/kryon_ctf_report.md",
) -> dict[str, Any]:
    """
    Autonomously solve CTF challenges from start to finish.

    Executes complete CTF workflow:
    1. Reconnaissance (nmap, gobuster, vulnerability scanning)
    2. Vulnerability analysis and exploit selection
    3. Exploitation attempts (automated)
    4. Privilege escalation (if needed)
    5. Flag hunting and extraction
    6. Reporting and documentation

    Args:
        target_ip: Target IP address or hostname
        target_type: Target OS type (linux, windows, auto)
        difficulty: Challenge difficulty (easy, medium, hard)
        max_time_hours: Maximum time to spend (hours)
        flags_needed: Specific flag names to find (user.txt, root.txt, etc.)
        output_report: Path to save final report

    Returns:
        Dictionary containing:
        - flags_found: List of discovered flags
        - exploitation_path: Steps taken to compromise
        - time_elapsed: Total time spent
        - services_exploited: Services successfully compromised
        - privilege_level: Final privilege level achieved
        - report_path: Path to detailed report
        - success: Whether flags were found

    Example:
        >>> # Solve TryHackMe room automatically
        >>> result = autonomous_ctf_solver(
        ...     target_ip="10.10.245.67",
        ...     target_type="linux",
        ...     difficulty="medium",
        ...     max_time_hours=2
        ... )
        >>>
        >>> if result['flags_found']:
        ...     for flag in result['flags_found']:
        ...         print(f"Flag: {flag['name']} = {flag['value']}")
        >>>
        >>> print(f"Exploitation path: {result['exploitation_path']}")
        >>> print(f"Report: {result['report_path']}")

    Autonomous Decision Points:
        - Port prioritization based on vulnerability likelihood
        - Exploit selection based on success probability
        - Privilege escalation path optimization
        - Flag location prediction
        - Fallback strategies on failure
    """
    results = {
        "flags_found": [],
        "exploitation_path": [],
        "time_elapsed": 0,
        "services_exploited": [],
        "privilege_level": "none",
        "report_path": output_report,
        "success": False,
        "error": None,
    }

    start_time = time.time()
    max_time_seconds = max_time_hours * 3600

    try:
        # ===== PHASE 0: STRATEGIC PLANNING =====
        from kryon.tools.autonomous.strategic_planner import StrategicPlanner

        planner = StrategicPlanner()

        # Create mission plan
        mission_objectives = ["initial_access", "privilege_escalation", "find_flags"]
        if difficulty == "hard":
            mission_objectives.append("lateral_movement")

        mission_plan = planner.autonomous_mission_planner(
            target_network=f"{target_ip}/32",
            objectives=mission_objectives,
            constraints={
                "max_time_hours": max_time_hours,
                "stealth_level": "medium",
                "noise_tolerance": "medium",
            },
            resources={
                "agents_available": 1,
                "tools": ["nmap", "gobuster", "sqlmap", "metasploit"],
            },
        )

        # T4-C2: read the ACTUAL keys StrategicPlanner produces (plan_id/stages/
        # estimated_time) with .get() defaults. The old code read "name"/
        # "objectives_order"/"estimated_time_hours" — keys that never exist — so a
        # KeyError('name') crashed FASE 0 before any scan and took down all three
        # autonomous capabilities (they all delegate here). These are log-only.
        _pp = mission_plan.get("primary_plan", {}) if isinstance(mission_plan, dict) else {}
        results["exploitation_path"].append(
            {
                "phase": "planning",
                "timestamp": datetime.now().isoformat(),
                "status": "completed",
                "plan_name": _pp.get("plan_id", "plan"),
                "objectives": _pp.get("stages", []),
                "estimated_time": _pp.get("estimated_time", 0),
            }
        )

        # ===== PHASE 1: AUTONOMOUS RECONNAISSANCE =====
        results["exploitation_path"].append(
            {
                "phase": "reconnaissance",
                "timestamp": datetime.now().isoformat(),
                "status": "starting",
            }
        )

        from kryon.tools.autonomous.auto_recon import full_auto_enumeration

        recon = full_auto_enumeration(
            target_ip=target_ip,
            deep_scan=difficulty in ["medium", "hard"],
            timeout=min(1800, max_time_seconds // 4),  # 30 min max or 25% of time
        )

        if not recon["success"] or not recon["open_ports"]:
            results["error"] = "Reconnaissance failed or no open ports found"
            return results

        results["exploitation_path"].append(
            {
                "phase": "reconnaissance",
                "status": "completed",
                "ports_found": len(recon["open_ports"]),
                "vulnerabilities_found": len(recon.get("vulnerabilities", [])),
            }
        )

        # ===== PHASE 1.5: CONTEXT ANALYSIS =====
        from kryon.tools.autonomous.context_analyzer import ContextAnalyzer

        analyzer = ContextAnalyzer()

        # Analyze reconnaissance data for intelligence
        recon_text = json.dumps(recon, indent=2)
        context_analysis = analyzer.autonomous_context_analysis(
            target_data={
                "recon_output": recon_text,
                "services": recon.get("services_detected", []),
            },
            operation_objective="initial_access",
        )

        results["exploitation_path"].append(
            {
                "phase": "context_analysis",
                "status": "completed",
                "credentials_found": len(context_analysis.get("credentials", [])),
                "hints_found": len(context_analysis.get("hints", [])),
                "attack_vectors": len(context_analysis.get("attack_surface", {}).get("endpoints", [])),
            }
        )

        # Extract any discovered credentials
        discovered_credentials = context_analysis.get("credentials", [])
        if discovered_credentials:
            results["exploitation_path"].append(
                {
                    "phase": "intelligence",
                    "status": "credentials_discovered",
                    "count": len(discovered_credentials),
                }
            )

        # ===== PHASE 2: LEARNING-BASED EXPLOIT SELECTION =====
        from kryon.tools.autonomous.adaptive_strategy import execute_with_adaptation
        from kryon.tools.autonomous.learning_engine import get_learned_recommendations

        # Get learned recommendations based on target profile
        target_profile = {
            "os": target_type if target_type != "auto" else "linux",
            "services": recon.get("services_detected", []),
            "difficulty": difficulty,
        }

        learned_recommendations = get_learned_recommendations(
            target_profile=target_profile,
            top_n=5,
            min_confidence=0.3,  # Lower threshold for CTF
        )

        results["exploitation_path"].append(
            {
                "phase": "learning_recommendations",
                "status": "completed",
                "recommendations_count": len(learned_recommendations.get("recommended_exploits", [])),
            }
        )

        # Try learned recommendations first, then fallback to decision engine
        exploits_to_try = []

        # Add learned recommendations
        for rec in learned_recommendations.get("recommended_exploits", []):
            exploits_to_try.append(
                {
                    "name": rec["exploit_name"],
                    "type": rec.get("exploit_type", "unknown"),
                    "source": "learned",
                    "success_rate": rec["success_rate"],
                    "service": rec.get("service_name", "unknown"),
                }
            )

        # Add decision engine recommendations as fallback
        from kryon.tools.autonomous.decision_engine import select_best_exploit

        for service in recon["services_detected"]:
            exploit_decision = select_best_exploit(
                service_name=service["name"],
                service_version=service["version"],
                target_os=target_type,
                difficulty=difficulty,
            )

            if exploit_decision["exploit_recommended"]:
                exploits_to_try.append(
                    {
                        "name": exploit_decision["exploit_name"],
                        "type": exploit_decision.get("exploit_type", "unknown"),
                        "source": "decision_engine",
                        "success_rate": exploit_decision.get("success_probability", 0.5),
                        "service": service,
                    }
                )

        # ===== PHASE 3: ADAPTIVE EXPLOITATION =====
        for exploit_info in exploits_to_try:
            if time.time() - start_time > max_time_seconds:
                break

            results["exploitation_path"].append(
                {
                    "phase": "exploitation",
                    "service": exploit_info.get("service", {}).get("name", exploit_info.get("service", "unknown")),
                    "exploit": exploit_info["name"],
                    "source": exploit_info["source"],
                    "timestamp": datetime.now().isoformat(),
                    "status": "attempting",
                }
            )

            # Execute with adaptive strategy
            service_info = exploit_info.get("service")
            if isinstance(service_info, str):
                # Find matching service from recon
                service_info = next(
                    (s for s in recon.get("services_detected", []) if s["name"] == service_info),
                    {"name": service_info, "version": "unknown", "port": 0},
                )

            # execute_with_adaptation is a @function_tool — call the raw fn, else
            # 'FunctionTool object is not callable' aborted the whole phase.
            exploit_result = execute_with_adaptation._raw_fn(
                target_ip=target_ip,
                exploit={"name": exploit_info["name"], "type": exploit_info["type"]},
                service=service_info,
                max_attempts=5,  # Allow adaptive retries
            )

            if exploit_result["success"]:
                service_name = service_info.get("name", "unknown") if isinstance(service_info, dict) else service_info
                results["services_exploited"].append(service_name)
                results["privilege_level"] = exploit_result.get("privilege_level", "user")

                results["exploitation_path"].append(
                    {
                        "phase": "exploitation",
                        "service": service_name,
                        "exploit": exploit_info["name"],
                        "status": "success",
                        "attempts_needed": exploit_result.get("attempts", 1),
                        "adaptations_applied": len(exploit_result.get("adaptations_applied", [])),
                        "defenses_bypassed": exploit_result.get("defenses_encountered", []),
                        "shell_obtained": exploit_result.get("shell_obtained", True),
                    }
                )

                # ===== PHASE 4: PRIVILEGE ESCALATION (if needed) =====
                if results["privilege_level"] != "root" and difficulty in ["medium", "hard"]:
                    privesc_result = _autonomous_privilege_escalation(
                        target_ip=target_ip, current_access=exploit_result, target_os=target_type
                    )

                    if privesc_result.get("escalated"):
                        results["privilege_level"] = "root"
                        results["exploitation_path"].append(
                            {
                                "phase": "privilege_escalation",
                                "status": "success",
                                "method": privesc_result["method"],
                            }
                        )
                    elif privesc_result.get("candidate_vectors"):
                        # T4-A6: record enumerated vectors WITHOUT claiming root —
                        # candidates identified, escalation not yet proven.
                        results["exploitation_path"].append(
                            {
                                "phase": "privilege_escalation",
                                "status": "vectors_identified",
                                "method": privesc_result["method"],
                                "candidate_count": len(privesc_result["candidate_vectors"]),
                            }
                        )

                # ===== PHASE 5: FLAG HUNTING =====
                flags_result = _autonomous_flag_hunting(
                    target_ip=target_ip,
                    access_level=results["privilege_level"],
                    flags_needed=flags_needed,
                )

                results["flags_found"].extend(flags_result["flags"])

                if flags_result["flags"]:
                    results["success"] = True
                    break  # Flags found, mission complete

        # ===== PHASE 6: LEARNING & RECORDING =====
        from kryon.tools.autonomous.learning_engine import record_operation

        # Record this operation for future learning
        operation_data = {
            "target_ip": target_ip,
            "target_type": target_profile["os"],
            "difficulty": difficulty,
            "services_detected": recon.get("services_detected", []),
        }

        operation_results = {
            "success": results["success"],
            "exploits_attempted": [
                {"name": e.get("exploit"), "type": e.get("type", "unknown")}
                for e in results["exploitation_path"]
                if e.get("phase") == "exploitation"
            ],
            "exploits_successful": [
                {"name": e.get("exploit"), "type": e.get("type", "unknown")}
                for e in results["exploitation_path"]
                if e.get("phase") == "exploitation" and e.get("status") == "success"
            ],
            "time_elapsed": time.time() - start_time,
            "privilege_level": results["privilege_level"],
            "flags_found": results["flags_found"],
            "defenses_encountered": [
                d
                for e in results["exploitation_path"]
                if e.get("defenses_bypassed")
                for d in e.get("defenses_bypassed", [])
            ],
        }

        try:
            operation_id = record_operation(operation_data, operation_results)
            results["operation_id"] = operation_id
            results["exploitation_path"].append(
                {"phase": "learning", "status": "recorded", "operation_id": operation_id}
            )
        except Exception as learning_error:
            # Don't fail the whole operation if learning fails
            results["exploitation_path"].append({"phase": "learning", "status": "failed", "error": str(learning_error)})

        # ===== PHASE 7: REPORTING =====
        results["time_elapsed"] = time.time() - start_time
        _generate_autonomous_report(results, output_report)

        # Dynamic plan adjustment if mission plan exists
        if mission_plan and not results["success"]:
            # Prepare progress update for plan adjustment
            progress_update = {
                "completed_objectives": [],
                "failed_objectives": mission_objectives,
                "time_elapsed_hours": results["time_elapsed"] / 3600,
                "issues": [results.get("error", "Unknown error")],
            }

            # Adjust plan for retry or next attempt
            try:
                adjusted_plan = planner.dynamic_plan_adjustment(
                    current_plan=mission_plan["primary_plan"],
                    current_progress=progress_update,
                    new_discoveries={
                        "services": recon.get("services_detected", []),
                        "credentials": discovered_credentials,
                    },
                )

                results["exploitation_path"].append(
                    {
                        "phase": "plan_adjustment",
                        "status": "completed",
                        "adjustments": len(adjusted_plan.get("adjustments_made", [])),
                    }
                )
            except Exception:
                pass  # Plan adjustment is optional

    except Exception as e:
        results["error"] = str(e)
        results["time_elapsed"] = time.time() - start_time

    return results


def autonomous_pentest(
    target_network: str,
    scope: list[str],
    max_targets: int = 10,
    max_time_hours: int = 8,
    stealth_level: str = "normal",
    output_dir: str = "/tmp/kryon_pentest",
) -> dict[str, Any]:
    """
    Autonomous penetration testing of network.

    Performs comprehensive pentest:
    1. Network discovery and mapping
    2. Service enumeration across targets
    3. Vulnerability assessment
    4. Automated exploitation attempts
    5. Lateral movement opportunities
    6. Data exfiltration simulation
    7. Comprehensive reporting

    Args:
        target_network: Network CIDR (e.g., 192.168.1.0/24)
        scope: List of allowed targets/subnets
        max_targets: Maximum number of targets to test
        max_time_hours: Maximum time for pentest
        stealth_level: low, normal, high (affects scan speed/noise)
        output_dir: Directory to save reports and evidence

    Returns:
        Dictionary containing pentest results

    Example:
        >>> result = autonomous_pentest(
        ...     target_network="192.168.1.0/24",
        ...     scope=["192.168.1.0/24"],
        ...     max_targets=20,
        ...     max_time_hours=8,
        ...     stealth_level="normal"
        ... )
        >>>
        >>> print(f"Hosts compromised: {len(result['compromised_hosts'])}")
        >>> print(f"Vulnerabilities found: {len(result['vulnerabilities'])}")
        >>> print(f"Report: {result['report_path']}")
    """
    results: dict[str, Any] = {
        "hosts_discovered": [],
        "hosts_out_of_scope": [],
        "compromised_hosts": [],
        "vulnerabilities": [],
        "lateral_movement_paths": [],
        "data_found": [],
        "report_path": "",
        "success": False,
        "error": None,
    }

    start_time = time.time()
    deadline = start_time + max_time_hours * 3600
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Phase 1: Network Discovery
        from kryon.tools.reconnaissance.nmap import nmap

        discovery = nmap._raw_fn(target=target_network, args="-sn" if stealth_level == "high" else "-F")
        discovered = discovery.get("hosts", []) or []

        # SCOPE ENFORCEMENT (fail-closed): an autonomous exploiter must NEVER
        # touch a host outside the authorized scope. Discovery may surface hosts
        # beyond ``scope`` (e.g. a /16 sweep whose authorization is a single /24);
        # those are recorded and skipped, never handed to the exploit loop.
        in_scope, out_of_scope = _partition_by_scope(discovered, scope)
        results["hosts_out_of_scope"] = [h.get("ip") for h in out_of_scope]
        if out_of_scope:
            logger.warning(
                "autonomous_pentest: %d discovered host(s) out of scope, skipped: %s",
                len(out_of_scope),
                results["hosts_out_of_scope"],
            )
        hosts = in_scope[:max_targets]
        results["hosts_discovered"] = hosts
        logger.info(
            "autonomous_pentest: %d in-scope host(s) to assess (budget %.1fh)",
            len(hosts),
            max_time_hours,
        )

        # Phase 2: Per-Host Autonomous Assessment
        for idx, host in enumerate(hosts):
            remaining = deadline - time.time()
            if remaining <= 0:
                logger.info(
                    "autonomous_pentest: wall budget exhausted after %d/%d hosts",
                    idx,
                    len(hosts),
                )
                break

            host_ip = host["ip"]
            # Derive the per-host budget from the remaining time split across the
            # hosts left, capped at _MAX_PER_HOST_SECONDS — not a hardcoded 1h.
            hosts_left = len(hosts) - idx
            per_host_seconds = min(_MAX_PER_HOST_SECONDS, remaining / hosts_left)

            host_result = autonomous_ctf_solver(
                target_ip=host_ip,
                max_time_hours=per_host_seconds / 3600.0,
                output_report=f"{output_dir}/host_{host_ip}_report.md",
            )
            _aggregate_host_result(results, host_ip, host_result)

        # Phase 3: Generate comprehensive report
        report_path = f"{output_dir}/pentest_report.md"
        _generate_pentest_report(results, report_path)
        results["report_path"] = report_path

        results["success"] = len(results["compromised_hosts"]) > 0

    except Exception as e:  # noqa: BLE001 — surface to the caller, log the trace
        logger.exception("autonomous_pentest failed")
        results["error"] = f"{type(e).__name__}: {e}"

    return results


def _partition_by_scope(
    hosts: list[dict[str, Any]], scope: list[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split discovered hosts into ``(in_scope, out_of_scope)``.

    A host with no IP, or whose IP falls in no scope entry, is out of scope.
    Fail-closed: an empty ``scope`` puts every host out of scope — an autonomous
    exploiter never touches a host it can't prove is authorized."""
    from kryon.onboarding.scope import host_in_scope

    in_scope: list[dict[str, Any]] = []
    out_of_scope: list[dict[str, Any]] = []
    for host in hosts:
        ip = (host.get("ip") or "").strip()
        if ip and host_in_scope(ip, scope):
            in_scope.append(host)
        else:
            out_of_scope.append(host)
    return in_scope, out_of_scope


def _aggregate_host_result(results: dict[str, Any], host_ip: str, host_result: dict[str, Any]) -> None:
    """Fold one host's ctf-solver result into the pentest aggregate.

    Fixes the long-standing gap where ``vulnerabilities`` / ``data_found`` were
    never populated: every confirmed exploited service is a vulnerability, and
    every recovered flag is loot — regardless of whether the host was fully
    compromised."""
    if host_result.get("success"):
        results["compromised_hosts"].append(
            {
                "ip": host_ip,
                "privilege_level": host_result.get("privilege_level", "none"),
                "flags_found": host_result.get("flags_found", []),
            }
        )
        results["lateral_movement_paths"].extend(_check_lateral_movement(host_ip, host_result))

    for service in host_result.get("services_exploited", []) or []:
        results["vulnerabilities"].append({"host": host_ip, "service": service, "type": "exploited-service"})
    for flag in host_result.get("flags_found", []) or []:
        results["data_found"].append({"host": host_ip, "flag": flag})


def autonomous_network_pivot(
    entry_point_ip: str,
    entry_credentials: dict[str, str],
    internal_network: str = "auto",
    max_depth: int = 3,
    objective: str = "domain_admin",
) -> dict[str, Any]:
    """
    Autonomous multi-stage network pivoting.

    Executes advanced pivoting:
    1. Establishes foothold on entry point
    2. Discovers internal networks
    3. Creates pivot tunnels automatically
    4. Enumerates and exploits internal hosts
    5. Lateral movement through network
    6. Achieves specified objective

    Args:
        entry_point_ip: Initial compromised host
        entry_credentials: SSH/RDP/SMB credentials for entry
        internal_network: Target internal network (auto-discovered if "auto")
        max_depth: Maximum pivot depth (hops)
        objective: Mission objective (domain_admin, data_exfil, persistence)

    Returns:
        Dictionary with pivoting results

    Example:
        >>> # After compromising DMZ host
        >>> result = autonomous_network_pivot(
        ...     entry_point_ip="10.10.10.5",
        ...     entry_credentials={"username": "www-data", "ssh_key": "/tmp/id_rsa"},
        ...     objective="domain_admin",
        ...     max_depth=3
        ... )
        >>>
        >>> print(f"Pivot chain: {result['pivot_chain']}")
        >>> print(f"Objective achieved: {result['objective_achieved']}")
    """
    results = {
        "pivot_chain": [],
        "compromised_hosts": [],
        "tunnels_created": [],
        "objective_achieved": False,
        "final_access_level": "none",
        "success": False,
        "error": None,
    }

    try:
        # Phase 1: Establish entry point pivot. ssh_dynamic_port_forward is now a
        # @function_tool (T4-M3), so call the raw callable behind it.
        from kryon.tools.pivoting import ssh_dynamic_port_forward

        socks_tunnel = ssh_dynamic_port_forward._raw_fn(
            ssh_host=entry_point_ip,
            ssh_user=entry_credentials.get("username"),
            ssh_key=entry_credentials.get("ssh_key"),
            socks_port=1080,
        )

        if not socks_tunnel["tunnel_active"]:
            results["error"] = "Failed to establish initial pivot"
            return results

        results["tunnels_created"].append({"type": "socks", "host": entry_point_ip, "port": 1080})

        results["pivot_chain"].append(entry_point_ip)

        # Phase 2: Discover internal network
        if internal_network == "auto":
            # Auto-discover internal networks
            internal_network = _discover_internal_networks(entry_point_ip, entry_credentials)

        # Phase 3: Enumerate internal hosts through pivot
        # (Use proxychains or configure tools to use SOCKS proxy)
        internal_hosts = _enumerate_through_pivot(network=internal_network, socks_proxy="127.0.0.1:1080")

        # Phase 4: Autonomous lateral movement
        current_depth = 1

        for host in internal_hosts:
            if current_depth >= max_depth:
                break

            # Attempt autonomous compromise
            compromise_result = _autonomous_compromise_through_pivot(target_ip=host["ip"], socks_proxy="127.0.0.1:1080")

            if compromise_result["success"]:
                results["compromised_hosts"].append(host["ip"])
                results["pivot_chain"].append(host["ip"])
                current_depth += 1

                # Check if objective achieved
                if _check_objective_achieved(objective, compromise_result):
                    results["objective_achieved"] = True
                    results["final_access_level"] = compromise_result["access_level"]
                    break

        results["success"] = results["objective_achieved"]

    except Exception as e:
        results["error"] = str(e)

    return results
