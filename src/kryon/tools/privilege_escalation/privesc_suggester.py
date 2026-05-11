"""
KRYON Privilege Escalation Suggester
======================================

AI-driven privilege escalation suggestion engine that analyzes
system information and suggests escalation vectors.

Primary Users:
- Pentest Agent (Alpha-Red)
- Vuln Hunter (Omega-Strike)
"""

import platform
from typing import Any

from .linux_privesc import (
    check_capabilities,
    check_docker_escape,
    check_sudo_permissions,
    find_suid_binaries,
    suggest_kernel_exploits,
)
from .windows_privesc import (
    check_always_install_elevated,
    check_token_privileges,
    find_stored_credentials,
    find_unquoted_service_paths,
)


def suggest_privesc_vectors(os_type: str | None = None, verbose: bool = True) -> dict[str, Any]:
    """
    Analyze system and suggest privilege escalation vectors.

    Args:
        os_type: Operating system ('linux' or 'windows', auto-detected if not specified)
        verbose: Include detailed suggestions

    Returns:
        Dictionary with suggested escalation vectors

    Example:
        >>> suggestions = suggest_privesc_vectors()
        >>> for vector in suggestions['high_priority']:
        ...     print(vector['method'], vector['description'])
    """
    result = {
        "success": False,
        "os": "",
        "high_priority": [],
        "medium_priority": [],
        "low_priority": [],
        "total_vectors": 0,
        "error": None,
    }

    try:
        # Detect OS if not specified
        if not os_type:
            os_type = platform.system().lower()
            if os_type == "linux":
                os_type = "linux"
            elif os_type == "windows":
                os_type = "windows"
            else:
                os_type = "unknown"

        result["os"] = os_type

        if os_type == "linux":
            vectors = _analyze_linux_privesc()
        elif os_type == "windows":
            vectors = _analyze_windows_privesc()
        else:
            result["error"] = f"Unsupported OS: {os_type}"
            return result

        # Categorize vectors by priority
        for vector in vectors:
            priority = vector.get("priority", "low")
            if priority == "high":
                result["high_priority"].append(vector)
            elif priority == "medium":
                result["medium_priority"].append(vector)
            else:
                result["low_priority"].append(vector)

        result["total_vectors"] = len(vectors)
        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def check_kernel_version(version: str | None = None) -> dict[str, Any]:
    """
    Check if kernel version is vulnerable to known exploits.

    Args:
        version: Kernel version (auto-detected if not provided)

    Returns:
        Dictionary with vulnerability information

    Example:
        >>> vuln_check = check_kernel_version()
    """
    result = {"success": False, "version": "", "vulnerable": False, "exploits": [], "error": None}

    try:
        from .linux_privesc import suggest_kernel_exploits

        exploit_result = suggest_kernel_exploits(version)

        if exploit_result.get("success"):
            result["version"] = exploit_result.get("kernel_version", "")
            result["exploits"] = exploit_result.get("exploits", [])
            result["vulnerable"] = len(result["exploits"]) > 0
            result["success"] = True
        else:
            result["error"] = exploit_result.get("error", "Failed to check kernel version")

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_system_for_privesc() -> dict[str, Any]:
    """
    Comprehensive system analysis for privilege escalation opportunities.

    Returns:
        Dictionary with complete analysis

    Example:
        >>> analysis = analyze_system_for_privesc()
    """
    result = {
        "success": False,
        "os": platform.system().lower(),
        "analysis": {},
        "recommendations": [],
        "error": None,
    }

    try:
        if result["os"] == "linux":
            result["analysis"] = _full_linux_analysis()
            result["recommendations"] = _generate_linux_recommendations(result["analysis"])
        elif result["os"] == "windows":
            result["analysis"] = _full_windows_analysis()
            result["recommendations"] = _generate_windows_recommendations(result["analysis"])

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


# Private helper functions for Linux


def _analyze_linux_privesc() -> list[dict[str, Any]]:
    """Analyze Linux system for privilege escalation vectors."""
    vectors = []

    # Check SUID binaries
    suid_result = find_suid_binaries(interesting_only=True)
    if suid_result.get("success") and suid_result.get("interesting"):
        for binary in suid_result["interesting"]:
            vectors.append(
                {
                    "method": "SUID Binary Exploitation",
                    "description": f"Exploit SUID binary: {binary['name']}",
                    "details": f"Path: {binary['path']}\nReference: {binary['gtfobins']}",
                    "priority": "high",
                }
            )

    # Check sudo permissions
    sudo_result = check_sudo_permissions()
    if sudo_result.get("success"):
        if sudo_result.get("can_sudo_all"):
            vectors.append(
                {
                    "method": "Sudo ALL Permissions",
                    "description": "User can execute all commands with sudo",
                    "details": "Use 'sudo su' or 'sudo /bin/bash' to get root shell",
                    "priority": "high",
                }
            )
        if sudo_result.get("no_password"):
            for perm in sudo_result["no_password"]:
                vectors.append(
                    {
                        "method": "Sudo NOPASSWD",
                        "description": f"Can execute without password: {perm}",
                        "details": "Check GTFOBins for exploitation techniques",
                        "priority": "high",
                    }
                )

    # Check kernel exploits
    kernel_result = suggest_kernel_exploits()
    if kernel_result.get("success") and kernel_result.get("exploits"):
        for exploit in kernel_result["exploits"]:
            vectors.append(
                {
                    "method": "Kernel Exploitation",
                    "description": f"Kernel vulnerable to {exploit['name']}",
                    "details": f"CVE: {exploit['cve']}\nAffected versions: {exploit['versions']}",
                    "priority": "high",
                }
            )

    # Check capabilities
    cap_result = check_capabilities()
    if cap_result.get("success") and cap_result.get("interesting"):
        for cap in cap_result["interesting"]:
            vectors.append(
                {
                    "method": "Capability Abuse",
                    "description": f"Interesting capability found: {cap}",
                    "details": "Binary has elevated capabilities that may be exploitable",
                    "priority": "medium",
                }
            )

    # Check Docker escape
    docker_result = check_docker_escape()
    if docker_result.get("success"):
        if docker_result.get("privileged"):
            vectors.append(
                {
                    "method": "Docker Privileged Escape",
                    "description": "Container running in privileged mode",
                    "details": "Can escape to host using privileged operations",
                    "priority": "high",
                }
            )
        if docker_result.get("docker_socket"):
            vectors.append(
                {
                    "method": "Docker Socket Abuse",
                    "description": "Docker socket mounted in container",
                    "details": "Can create privileged container to escape",
                    "priority": "high",
                }
            )

    return vectors


def _full_linux_analysis() -> dict[str, Any]:
    """Perform full Linux privilege escalation analysis."""
    from .linux_privesc import enumerate_linux_privesc

    return enumerate_linux_privesc(verbose=True)


def _generate_linux_recommendations(analysis: dict[str, Any]) -> list[str]:
    """Generate recommendations based on Linux analysis."""
    recommendations = []

    if analysis.get("suid_binaries"):
        recommendations.append(
            "Review SUID binaries with GTFOBins (https://gtfobins.github.io/) for privilege escalation techniques"
        )

    if analysis.get("sudo_permissions"):
        recommendations.append(
            "Analyze sudo permissions - look for NOPASSWD entries and commands "
            "that can be abused for privilege escalation"
        )

    if analysis.get("writable_files"):
        recommendations.append(
            "Check writable files for sensitive configuration files or scripts that run with elevated privileges"
        )

    if analysis.get("cron_jobs"):
        recommendations.append("Review cron jobs for writable scripts or paths that can be hijacked")

    if not recommendations:
        recommendations.append(
            "No obvious privilege escalation vectors found. "
            "Consider kernel exploits, misconfigurations, or application vulnerabilities"
        )

    return recommendations


# Private helper functions for Windows


def _analyze_windows_privesc() -> list[dict[str, Any]]:
    """Analyze Windows system for privilege escalation vectors."""
    vectors = []

    # Check unquoted service paths
    unquoted_result = find_unquoted_service_paths()
    if unquoted_result.get("success") and unquoted_result.get("services"):
        for service in unquoted_result["services"]:
            vectors.append(
                {
                    "method": "Unquoted Service Path",
                    "description": f"Service with unquoted path: {service}",
                    "details": "Place malicious executable in path to hijack service",
                    "priority": "high",
                }
            )

    # Check AlwaysInstallElevated
    elevated_result = check_always_install_elevated()
    if elevated_result.get("success") and elevated_result.get("enabled"):
        vectors.append(
            {
                "method": "AlwaysInstallElevated",
                "description": "AlwaysInstallElevated is enabled",
                "details": "Create malicious MSI to gain SYSTEM privileges",
                "priority": "high",
            }
        )

    # Check token privileges
    priv_result = check_token_privileges()
    if priv_result.get("success") and priv_result.get("dangerous_privs"):
        for priv in priv_result["dangerous_privs"]:
            vectors.append(
                {
                    "method": "Token Privilege Abuse",
                    "description": f"Dangerous privilege enabled: {priv}",
                    "details": "Use privilege escalation tools (e.g., JuicyPotato, PrintSpoofer)",
                    "priority": "high",
                }
            )

    # Check stored credentials
    creds_result = find_stored_credentials()
    if creds_result.get("success"):
        if creds_result.get("cmdkey"):
            vectors.append(
                {
                    "method": "Stored Credentials",
                    "description": "Found stored credentials via cmdkey",
                    "details": "Use 'runas /savecred' to execute commands as stored user",
                    "priority": "medium",
                }
            )
        if creds_result.get("unattend_files"):
            vectors.append(
                {
                    "method": "Unattend.xml Credentials",
                    "description": "Found unattend.xml files with potential credentials",
                    "details": "Review unattend.xml for plaintext passwords",
                    "priority": "high",
                }
            )

    return vectors


def _full_windows_analysis() -> dict[str, Any]:
    """Perform full Windows privilege escalation analysis."""
    from .windows_privesc import enumerate_windows_privesc

    return enumerate_windows_privesc()


def _generate_windows_recommendations(analysis: dict[str, Any]) -> list[str]:
    """Generate recommendations based on Windows analysis."""
    recommendations = []

    if analysis.get("unquoted_services"):
        recommendations.append("Exploit unquoted service paths by placing malicious executables in paths with spaces")

    if analysis.get("always_install_elevated"):
        recommendations.append("Generate malicious MSI using msfvenom and install to gain SYSTEM privileges")

    if analysis.get("weak_permissions"):
        recommendations.append("Check service binary permissions and replace with malicious binaries")

    if analysis.get("auto_logon"):
        recommendations.append("Auto-logon credentials found in registry - use to authenticate as that user")

    if not recommendations:
        recommendations.append(
            "No obvious privilege escalation vectors found. Consider token abuse, DLL hijacking, or kernel exploits"
        )

    return recommendations
