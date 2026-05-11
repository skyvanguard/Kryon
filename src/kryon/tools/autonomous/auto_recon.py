"""
KRYON Autonomous Reconnaissance
=================================

Automated reconnaissance and enumeration for autonomous operations.

Clearance Level: Omega-Command (Autonomous Operations Authority)
Mission: Automated target enumeration with minimal human intervention

This module provides comprehensive automated reconnaissance including:
- Port scanning (nmap)
- Service detection and versioning
- Directory/file enumeration (gobuster, ffuf)
- Vulnerability scanning
- OS fingerprinting
- Banner grabbing
"""

import re
import shlex
import subprocess
import time
from typing import Any


def full_auto_enumeration(target_ip: str, deep_scan: bool = False, timeout: int = 1800) -> dict[str, Any]:
    """
    Perform complete autonomous enumeration of target.

    This function orchestrates multiple reconnaissance tools to gather
    comprehensive information about the target with minimal user intervention.

    Args:
        target_ip: Target IP address or hostname
        deep_scan: If True, performs more thorough (slower) scans
        timeout: Maximum time in seconds for enumeration (default: 30 min)

    Returns:
        Dictionary containing:
        - success: Whether enumeration completed successfully
        - open_ports: List of open ports with details
        - services_detected: List of services with versions
        - vulnerabilities: List of potential vulnerabilities found
        - os_detection: Operating system detection results
        - http_endpoints: Discovered HTTP endpoints (if web server found)
        - error: Error message if failed

    Example:
        >>> result = full_auto_enumeration(
        ...     target_ip="10.10.10.5",
        ...     deep_scan=True,
        ...     timeout=1800
        ... )
        >>> print(f"Found {len(result['open_ports'])} open ports")
        >>> print(f"Detected services: {result['services_detected']}")
    """
    start_time = time.time()
    max_time = start_time + timeout

    results = {
        "success": False,
        "open_ports": [],
        "services_detected": [],
        "vulnerabilities": [],
        "os_detection": {},
        "http_endpoints": [],
        "enumeration_time": 0,
        "error": None,
    }

    try:
        # Phase 1: Quick port scan
        print(f"[*] Phase 1: Port scanning {target_ip}...")
        port_scan_result = _quick_port_scan(target_ip, deep_scan)

        if not port_scan_result["success"]:
            results["error"] = "Port scan failed"
            return results

        results["open_ports"] = port_scan_result["ports"]
        results["os_detection"] = port_scan_result.get("os", {})

        # Phase 2: Service detection
        print("[*] Phase 2: Service detection...")
        service_result = _detect_services(target_ip, results["open_ports"])
        results["services_detected"] = service_result["services"]

        # Phase 3: HTTP enumeration (if web server found)
        http_ports = [p for p in results["open_ports"] if p["service"] in ["http", "https", "web"]]
        if http_ports and time.time() < max_time:
            print("[*] Phase 3: Web enumeration...")
            for port_info in http_ports:
                port = port_info["port"]
                protocol = "https" if port == 443 or port_info["service"] == "https" else "http"

                web_enum_result = _enumerate_web(
                    target_ip, port, protocol, timeout=min(600, int(max_time - time.time()))
                )

                if web_enum_result["success"]:
                    results["http_endpoints"].extend(web_enum_result["endpoints"])
                    if web_enum_result.get("vulnerabilities"):
                        results["vulnerabilities"].extend(web_enum_result["vulnerabilities"])

        # Phase 4: Vulnerability assessment (if time permits)
        if deep_scan and time.time() < max_time:
            print("[*] Phase 4: Vulnerability assessment...")
            vuln_result = _vulnerability_assessment(target_ip, results["services_detected"])
            if vuln_result.get("vulnerabilities"):
                results["vulnerabilities"].extend(vuln_result["vulnerabilities"])

        results["success"] = len(results["open_ports"]) > 0
        results["enumeration_time"] = time.time() - start_time

    except Exception as e:
        results["error"] = str(e)
        results["enumeration_time"] = time.time() - start_time

    return results


def _quick_port_scan(target_ip: str, deep: bool = False) -> dict[str, Any]:
    """
    Perform quick port scan using nmap.

    Args:
        target_ip: Target to scan
        deep: If True, scan all 65535 ports (slow)

    Returns:
        Dict with success status, ports, and OS detection
    """
    result = {"success": False, "ports": [], "os": {}}

    try:
        # Construct nmap command
        if deep:
            # Full port scan (slower but comprehensive)
            cmd = f"nmap -p- -T4 -sV -O --version-intensity 5 {shlex.quote(target_ip)} -oN - 2>/dev/null"
        else:
            # Top 1000 ports (fast)
            cmd = f"nmap -F -T4 -sV {shlex.quote(target_ip)} -oN - 2>/dev/null"

        # Execute nmap
        output = subprocess.check_output(cmd, shell=True, text=True, timeout=300)  # nosemgrep: subprocess-shell-true

        # Parse output
        ports = _parse_nmap_output(output)
        result["ports"] = ports
        result["success"] = len(ports) > 0

        # Extract OS detection if available
        os_match = re.search(r"Running: (.+)", output)
        if os_match:
            result["os"] = {"type": os_match.group(1).strip()}

    except subprocess.TimeoutExpired:
        result["error"] = "Nmap scan timed out"
    except subprocess.CalledProcessError:
        # Nmap not available, fallback to basic scan
        result = _fallback_port_scan(target_ip)
    except Exception as e:
        result["error"] = str(e)

    return result


def _parse_nmap_output(output: str) -> list[dict[str, Any]]:
    """Parse nmap output to extract open ports and services."""
    ports = []

    # Extract open ports
    port_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?"
    matches = re.findall(port_pattern, output)

    for match in matches:
        port_num, protocol, service, version = match
        ports.append(
            {
                "port": int(port_num),
                "protocol": protocol,
                "service": service,
                "version": version.strip() if version else "unknown",
                "state": "open",
            }
        )

    return ports


def _fallback_port_scan(target_ip: str) -> dict[str, Any]:
    """
    Fallback port scanner using raw sockets when nmap is unavailable.

    Scans common ports only to avoid long execution times.
    """
    import socket

    common_ports = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        8080: "http-alt",
        8443: "https-alt",
    }

    result = {"success": False, "ports": []}
    open_ports = []

    for port, service in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            connection_result = sock.connect_ex((target_ip, port))

            if connection_result == 0:
                open_ports.append(
                    {
                        "port": port,
                        "protocol": "tcp",
                        "service": service,
                        "version": "unknown",
                        "state": "open",
                    }
                )

            sock.close()
        except Exception:
            continue

    result["ports"] = open_ports
    result["success"] = len(open_ports) > 0

    return result


def _detect_services(target_ip: str, ports: list[dict]) -> dict[str, Any]:
    """
    Detect service versions on open ports.

    Attempts banner grabbing and service fingerprinting.
    """
    services = []

    for port_info in ports:
        port = port_info["port"]
        service_name = port_info.get("service", "unknown")

        # Try banner grabbing for common services
        banner = _grab_banner(target_ip, port, service_name)

        service_entry = {
            "name": service_name,
            "port": port,
            "version": port_info.get("version", "unknown"),
            "banner": banner if banner else None,
            "protocol": port_info.get("protocol", "tcp"),
        }

        services.append(service_entry)

    return {"services": services}


def _grab_banner(target_ip: str, port: int, service: str) -> str | None:
    """Attempt to grab service banner."""
    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target_ip, port))

        # Send appropriate probe based on service
        if service in ["http", "https", "web"]:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
        elif service == "smtp":
            sock.send(b"EHLO test\r\n")
        elif service in ["ftp", "ssh"]:
            pass  # Wait for server banner
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore")
        sock.close()

        return banner.strip() if banner else None

    except Exception:
        return None


def _enumerate_web(target_ip: str, port: int, protocol: str, timeout: int = 600) -> dict[str, Any]:
    """
    Enumerate web server directories and files.

    Uses gobuster if available, falls back to simple enumeration.
    """
    result = {"success": False, "endpoints": [], "vulnerabilities": []}

    base_url = f"{protocol}://{target_ip}:{port}"

    try:
        # Try gobuster first
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        cmd = f"gobuster dir -u {shlex.quote(base_url)} -w {wordlist} -t 20 -q --timeout 10s 2>/dev/null"

        output = subprocess.check_output(
            # nosemgrep: subprocess-shell-true
            cmd,
            # nosemgrep: subprocess-shell-true
            shell=True,
            text=True,
            timeout=min(timeout, 300),
        )  # nosemgrep: subprocess-shell-true

        # Parse gobuster output
        endpoints = _parse_gobuster_output(output, base_url)
        result["endpoints"] = endpoints
        result["success"] = len(endpoints) > 0

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        # Gobuster not available or failed, try basic enumeration
        result = _fallback_web_enum(base_url)

    return result


def _parse_gobuster_output(output: str, base_url: str) -> list[str]:
    """Parse gobuster output to extract discovered paths."""
    endpoints = []

    # Gobuster format: /path (Status: 200) [Size: 1234]
    pattern = r"(/\S+)\s+\(Status: (\d+)\)"
    matches = re.findall(pattern, output)

    for path, status in matches:
        if status in ["200", "301", "302", "401", "403"]:
            endpoints.append(f"{base_url}{path}")

    return endpoints


def _fallback_web_enum(base_url: str) -> dict[str, Any]:
    """Fallback web enumeration using common paths."""
    import requests

    common_paths = [
        "/admin",
        "/login",
        "/api",
        "/robots.txt",
        "/sitemap.xml",
        "/.git",
        "/config",
        "/backup",
        "/wp-admin",
        "/phpmyadmin",
    ]

    result = {"success": False, "endpoints": [], "vulnerabilities": []}

    for path in common_paths:
        try:
            url = f"{base_url}{path}"
            # nosemgrep: disabled-cert-validation
            response = requests.get(
                url, timeout=5, verify=False, allow_redirects=False
            )  # nosemgrep: disabled-cert-validation

            if response.status_code in [200, 301, 302, 401, 403]:
                result["endpoints"].append(url)

                # Check for common vulnerabilities
                if path == "/.git" and response.status_code == 200:
                    result["vulnerabilities"].append(
                        {
                            "type": "exposed_git",
                            "severity": "high",
                            "description": "Exposed .git directory",
                        }
                    )

        except Exception:
            continue

    result["success"] = len(result["endpoints"]) > 0
    return result


def _vulnerability_assessment(target_ip: str, services: list[dict]) -> dict[str, Any]:
    """
    Basic vulnerability assessment based on detected services.

    Checks for known vulnerable versions and common misconfigurations.
    """
    vulnerabilities = []

    # CVE database (simplified)
    known_vulns = {
        "Apache 2.4.49": {
            "cve": "CVE-2021-41773",
            "severity": "critical",
            "description": "Path traversal and RCE vulnerability",
        },
        "Apache 2.4.50": {
            "cve": "CVE-2021-42013",
            "severity": "critical",
            "description": "Path traversal and RCE vulnerability",
        },
        "OpenSSH 7.6": {
            "cve": "CVE-2018-15473",
            "severity": "medium",
            "description": "Username enumeration vulnerability",
        },
        "MySQL 5.7": {
            "cve": "CVE-2020-14765",
            "severity": "medium",
            "description": "Privilege escalation vulnerability",
        },
    }

    for service in services:
        version = service.get("version", "")

        # Check against known vulnerabilities
        for vuln_version, vuln_info in known_vulns.items():
            if vuln_version.lower() in version.lower():
                vulnerabilities.append({"service": service["name"], "port": service["port"], **vuln_info})

    return {"vulnerabilities": vulnerabilities}


# Convenience wrapper functions


def quick_recon(target_ip: str) -> dict[str, Any]:
    """
    Quick reconnaissance (top 1000 ports, no deep scan).

    Args:
        target_ip: Target to scan

    Returns:
        Recon results dictionary
    """
    return full_auto_enumeration(target_ip, deep_scan=False, timeout=300)


def deep_recon(target_ip: str) -> dict[str, Any]:
    """
    Deep reconnaissance (all ports, vulnerability scanning).

    Args:
        target_ip: Target to scan

    Returns:
        Comprehensive recon results
    """
    return full_auto_enumeration(target_ip, deep_scan=True, timeout=1800)
