"""
SKYNET Linux Privilege Escalation Module
=========================================

Linux privilege escalation enumeration and exploitation tools.
Inspired by LinPEAS, LinEnum, and linux-exploit-suggester.

Primary Users:
- T-800 Infiltrator (Alpha-Red)
- T-1000 Advanced Hunter (Omega-Strike)
"""

import os
import re
from typing import Dict, List, Any, Optional
from skynet.tools.common import generic_linux_command


def enumerate_linux_privesc(verbose: bool = False) -> Dict[str, Any]:
    """
    Comprehensive Linux privilege escalation enumeration.

    Args:
        verbose: Include detailed output

    Returns:
        Dictionary with enumeration results

    Example:
        >>> results = enumerate_linux_privesc(verbose=True)
        >>> print(results['suid_binaries'])
    """
    result = {
        "success": False,
        "system_info": {},
        "suid_binaries": [],
        "sudo_permissions": [],
        "writable_files": [],
        "capabilities": [],
        "cron_jobs": [],
        "network_info": {},
        "users": [],
        "groups": [],
        "error": None
    }

    try:
        # Gather system information
        result["system_info"] = _get_system_info()

        # Find SUID binaries
        suid_result = find_suid_binaries()
        if suid_result.get("success"):
            result["suid_binaries"] = suid_result.get("binaries", [])

        # Check sudo permissions
        sudo_result = check_sudo_permissions()
        if sudo_result.get("success"):
            result["sudo_permissions"] = sudo_result.get("permissions", [])

        # Find writable files
        writable_result = find_writable_files()
        if writable_result.get("success"):
            result["writable_files"] = writable_result.get("files", [])

        # Check capabilities
        cap_result = check_capabilities()
        if cap_result.get("success"):
            result["capabilities"] = cap_result.get("capabilities", [])

        # Find cron jobs
        cron_result = find_cron_jobs()
        if cron_result.get("success"):
            result["cron_jobs"] = cron_result.get("cron_jobs", [])

        # Get network information
        result["network_info"] = _get_network_info()

        # Get users and groups
        result["users"] = _get_users()
        result["groups"] = _get_groups()

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def find_suid_binaries(
    search_paths: Optional[List[str]] = None,
    interesting_only: bool = False
) -> Dict[str, Any]:
    """
    Find SUID/SGID binaries on the system.

    Args:
        search_paths: Paths to search (defaults to common paths)
        interesting_only: Only return potentially exploitable binaries

    Returns:
        Dictionary with SUID/SGID binaries

    Example:
        >>> binaries = find_suid_binaries(interesting_only=True)
    """
    result = {
        "success": False,
        "binaries": [],
        "count": 0,
        "interesting": [],
        "error": None
    }

    try:
        # Common interesting SUID binaries that can lead to privilege escalation
        interesting_binaries = [
            'nmap', 'vim', 'vi', 'find', 'bash', 'sh', 'less', 'more',
            'nano', 'cp', 'mv', 'awk', 'man', 'wget', 'curl', 'python',
            'python2', 'python3', 'perl', 'ruby', 'lua', 'php', 'gcc',
            'cc', 'ld', 'as', 'systemctl', 'journalctl', 'docker', 'screen',
            'tmux', 'script', 'socat', 'rlwrap', 'base64', 'openssl'
        ]

        # Default search paths
        if not search_paths:
            search_paths = ['/']

        # Find SUID binaries
        cmd_result = generic_linux_command(
            "find",
            f"{' '.join(search_paths)} -type f -perm -4000 2>/dev/null"
        )

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            binaries = [line.strip() for line in output.split('\n') if line.strip()]

            result["success"] = True
            result["binaries"] = binaries
            result["count"] = len(binaries)

            # Find interesting binaries
            for binary in binaries:
                binary_name = os.path.basename(binary)
                if binary_name in interesting_binaries:
                    result["interesting"].append({
                        "path": binary,
                        "name": binary_name,
                        "gtfobins": f"https://gtfobins.github.io/gtfobins/{binary_name}/"
                    })

            # Return only interesting if requested
            if interesting_only:
                result["binaries"] = [item["path"] for item in result["interesting"]]

        else:
            result["error"] = cmd_result.get("error", "find command failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def find_writable_files(
    search_paths: Optional[List[str]] = None,
    exclude_proc: bool = True
) -> Dict[str, Any]:
    """
    Find world-writable files and directories.

    Args:
        search_paths: Paths to search
        exclude_proc: Exclude /proc and /sys

    Returns:
        Dictionary with writable files

    Example:
        >>> writable = find_writable_files()
    """
    result = {
        "success": False,
        "files": [],
        "directories": [],
        "count": 0,
        "error": None
    }

    try:
        if not search_paths:
            search_paths = ['/etc', '/home', '/var', '/tmp', '/opt']

        exclude_args = ""
        if exclude_proc:
            exclude_args = "-path /proc -prune -o -path /sys -prune -o"

        # Find world-writable files
        cmd_result = generic_linux_command(
            "find",
            f"{' '.join(search_paths)} {exclude_args} -type f -perm -002 2>/dev/null"
        )

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            files = [line.strip() for line in output.split('\n') if line.strip()]

            result["files"] = files
            result["count"] = len(files)

        # Find world-writable directories
        dir_result = generic_linux_command(
            "find",
            f"{' '.join(search_paths)} {exclude_args} -type d -perm -002 2>/dev/null"
        )

        if dir_result.get("success"):
            output = dir_result.get("output", "")
            directories = [line.strip() for line in output.split('\n') if line.strip()]
            result["directories"] = directories

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def check_sudo_permissions() -> Dict[str, Any]:
    """
    Check sudo permissions for current user.

    Returns:
        Dictionary with sudo permissions

    Example:
        >>> sudo = check_sudo_permissions()
    """
    result = {
        "success": False,
        "permissions": [],
        "can_sudo_all": False,
        "no_password": [],
        "error": None
    }

    try:
        # Check sudo -l
        cmd_result = generic_linux_command("sudo", "-l")

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")

            # Check for ALL permissions
            if "(ALL : ALL)" in output or "(ALL) ALL" in output:
                result["can_sudo_all"] = True

            # Check for NOPASSWD
            if "NOPASSWD" in output:
                # Extract commands that don't require password
                for line in output.split('\n'):
                    if "NOPASSWD" in line:
                        result["no_password"].append(line.strip())

            result["permissions"] = output.split('\n')
            result["success"] = True
        else:
            # User might not have sudo permissions
            result["permissions"] = ["No sudo permissions or cannot check"]
            result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def suggest_kernel_exploits(kernel_version: Optional[str] = None) -> Dict[str, Any]:
    """
    Suggest kernel exploits based on kernel version.

    Args:
        kernel_version: Kernel version (auto-detected if not provided)

    Returns:
        Dictionary with suggested exploits

    Example:
        >>> exploits = suggest_kernel_exploits()
    """
    result = {
        "success": False,
        "kernel_version": "",
        "exploits": [],
        "error": None
    }

    try:
        # Get kernel version if not provided
        if not kernel_version:
            cmd_result = generic_linux_command("uname", "-r")
            if cmd_result.get("success"):
                kernel_version = cmd_result.get("output", "").strip()

        result["kernel_version"] = kernel_version

        # Known kernel exploits database (simplified)
        kernel_exploits = {
            "2.6": [
                {"name": "DirtyCOW", "cve": "CVE-2016-5195", "versions": "2.6.22 - 4.8.3"},
                {"name": "RDS", "cve": "CVE-2010-3904", "versions": "2.6.30 - 2.6.36"},
            ],
            "3.": [
                {"name": "DirtyCOW", "cve": "CVE-2016-5195", "versions": "2.6.22 - 4.8.3"},
                {"name": "Overlayfs", "cve": "CVE-2015-1328", "versions": "3.13.0 - 3.19.0"},
            ],
            "4.": [
                {"name": "DirtyCOW", "cve": "CVE-2016-5195", "versions": "2.6.22 - 4.8.3"},
                {"name": "AF_PACKET", "cve": "CVE-2016-8655", "versions": "4.4.0 - 4.8.12"},
            ],
        }

        # Match kernel version to exploits
        for version_prefix, exploits in kernel_exploits.items():
            if kernel_version.startswith(version_prefix):
                result["exploits"].extend(exploits)

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def check_capabilities() -> Dict[str, Any]:
    """
    Check for binaries with capabilities set.

    Returns:
        Dictionary with capabilities

    Example:
        >>> caps = check_capabilities()
    """
    result = {
        "success": False,
        "capabilities": [],
        "interesting": [],
        "error": None
    }

    try:
        # Use getcap to find capabilities
        cmd_result = generic_linux_command("getcap", "-r / 2>/dev/null")

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            capabilities = [line.strip() for line in output.split('\n') if line.strip()]

            result["capabilities"] = capabilities

            # Identify interesting capabilities
            interesting_caps = ['cap_setuid', 'cap_setgid', 'cap_dac_override', 'cap_sys_admin']
            for cap_line in capabilities:
                for interesting in interesting_caps:
                    if interesting in cap_line.lower():
                        result["interesting"].append(cap_line)
                        break

            result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def find_cron_jobs() -> Dict[str, Any]:
    """
    Find cron jobs and check for misconfigurations.

    Returns:
        Dictionary with cron jobs

    Example:
        >>> crons = find_cron_jobs()
    """
    result = {
        "success": False,
        "cron_jobs": [],
        "writable_crons": [],
        "error": None
    }

    try:
        cron_locations = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/var/spool/cron/',
            '/var/spool/cron/crontabs/',
        ]

        all_crons = []

        for location in cron_locations:
            if os.path.exists(location):
                if os.path.isfile(location):
                    cmd_result = generic_linux_command("cat", location)
                    if cmd_result.get("success"):
                        all_crons.append({
                            "location": location,
                            "content": cmd_result.get("output", "")
                        })
                elif os.path.isdir(location):
                    cmd_result = generic_linux_command("ls", f"-la {location}")
                    if cmd_result.get("success"):
                        all_crons.append({
                            "location": location,
                            "content": cmd_result.get("output", "")
                        })

        result["cron_jobs"] = all_crons

        # Check for writable cron files
        for location in cron_locations:
            if os.path.exists(location):
                cmd_result = generic_linux_command("find", f"{location} -writable 2>/dev/null")
                if cmd_result.get("success"):
                    writable = cmd_result.get("output", "").strip()
                    if writable:
                        result["writable_crons"].append(writable)

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def check_docker_escape() -> Dict[str, Any]:
    """
    Check for Docker container escape vectors.

    Returns:
        Dictionary with Docker escape possibilities

    Example:
        >>> docker_check = check_docker_escape()
    """
    result = {
        "success": False,
        "in_container": False,
        "escape_vectors": [],
        "privileged": False,
        "docker_socket": False,
        "error": None
    }

    try:
        # Check if we're in a container
        if os.path.exists('/.dockerenv'):
            result["in_container"] = True

        # Check for privileged mode
        cmd_result = generic_linux_command("cat", "/proc/self/status")
        if cmd_result.get("success"):
            if "CapEff:	0000003fffffffff" in cmd_result.get("output", ""):
                result["privileged"] = True
                result["escape_vectors"].append({
                    "method": "Privileged Container",
                    "description": "Container is running in privileged mode"
                })

        # Check for Docker socket
        if os.path.exists('/var/run/docker.sock'):
            result["docker_socket"] = True
            result["escape_vectors"].append({
                "method": "Docker Socket",
                "description": "Docker socket is mounted in container"
            })

        # Check for sensitive mounts
        cmd_result = generic_linux_command("mount", "")
        if cmd_result.get("success"):
            mounts = cmd_result.get("output", "")
            if "/proc" in mounts or "/sys" in mounts:
                result["escape_vectors"].append({
                    "method": "Sensitive Mounts",
                    "description": "Sensitive filesystems mounted"
                })

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


# Helper functions

def _get_system_info() -> Dict[str, str]:
    """Get basic system information."""
    info = {}

    commands = {
        "hostname": "hostname",
        "kernel": "uname -r",
        "os": "cat /etc/os-release",
        "arch": "uname -m",
        "user": "whoami",
        "id": "id"
    }

    for key, cmd in commands.items():
        parts = cmd.split()
        result = generic_linux_command(parts[0], " ".join(parts[1:]) if len(parts) > 1 else "")
        if result.get("success"):
            info[key] = result.get("output", "").strip()

    return info


def _get_network_info() -> Dict[str, str]:
    """Get network information."""
    info = {}

    commands = {
        "interfaces": "ip a",
        "routes": "ip route",
        "listening": "ss -tuln",
        "connections": "ss -tun"
    }

    for key, cmd in commands.items():
        parts = cmd.split()
        result = generic_linux_command(parts[0], " ".join(parts[1:]))
        if result.get("success"):
            info[key] = result.get("output", "").strip()

    return info


def _get_users() -> List[str]:
    """Get list of users."""
    result = generic_linux_command("cat", "/etc/passwd")
    if result.get("success"):
        users = []
        for line in result.get("output", "").split('\n'):
            if line.strip():
                users.append(line.split(':')[0])
        return users
    return []


def _get_groups() -> List[str]:
    """Get list of groups."""
    result = generic_linux_command("cat", "/etc/group")
    if result.get("success"):
        groups = []
        for line in result.get("output", "").split('\n'):
            if line.strip():
                groups.append(line.split(':')[0])
        return groups
    return []
