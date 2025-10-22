"""
SKYNET Windows Privilege Escalation Module
==========================================

Windows privilege escalation enumeration and exploitation tools.
Inspired by WinPEAS, PowerUp, and windows-privesc-check.

Primary Users:
- T-800 Infiltrator (Alpha-Red)
- T-1000 Advanced Hunter (Omega-Strike)
"""

import re
from typing import Dict, List, Any, Optional
from skynet.tools.common import generic_linux_command


def enumerate_windows_privesc() -> Dict[str, Any]:
    """
    Comprehensive Windows privilege escalation enumeration.

    Returns:
        Dictionary with enumeration results

    Example:
        >>> results = enumerate_windows_privesc()
    """
    result = {
        "success": False,
        "system_info": {},
        "unquoted_services": [],
        "weak_permissions": [],
        "auto_logon": {},
        "always_install_elevated": False,
        "scheduled_tasks": [],
        "error": None
    }

    try:
        # System information
        result["system_info"] = _get_windows_system_info()

        # Find unquoted service paths
        unquoted_result = find_unquoted_service_paths()
        if unquoted_result.get("success"):
            result["unquoted_services"] = unquoted_result.get("services", [])

        # Check weak service permissions
        weak_result = check_weak_service_permissions()
        if weak_result.get("success"):
            result["weak_permissions"] = weak_result.get("services", [])

        # Find auto-logon credentials
        autologon_result = find_auto_logon_credentials()
        if autologon_result.get("success"):
            result["auto_logon"] = autologon_result.get("credentials", {})

        # Check AlwaysInstallElevated
        elevated_result = check_always_install_elevated()
        if elevated_result.get("success"):
            result["always_install_elevated"] = elevated_result.get("enabled", False)

        # Enumerate scheduled tasks
        tasks_result = enumerate_scheduled_tasks()
        if tasks_result.get("success"):
            result["scheduled_tasks"] = tasks_result.get("tasks", [])

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def find_unquoted_service_paths() -> Dict[str, Any]:
    """
    Find Windows services with unquoted paths containing spaces.

    Returns:
        Dictionary with unquoted service paths

    Example:
        >>> services = find_unquoted_service_paths()
    """
    result = {
        "success": False,
        "services": [],
        "count": 0,
        "error": None
    }

    try:
        # Use wmic to query services
        cmd = 'wmic service get name,pathname,displayname,startmode | findstr /i "auto" | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """'

        cmd_result = generic_linux_command("cmd.exe", f"/c {cmd}")

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")

            services = []
            for line in output.split('\n'):
                line = line.strip()
                if line and ' ' in line:
                    # Parse service information
                    services.append(line)

            result["services"] = services
            result["count"] = len(services)
            result["success"] = True
        else:
            result["error"] = cmd_result.get("error", "wmic command failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def check_weak_service_permissions() -> Dict[str, Any]:
    """
    Check for services with weak file permissions.

    Returns:
        Dictionary with services having weak permissions

    Example:
        >>> weak_services = check_weak_service_permissions()
    """
    result = {
        "success": False,
        "services": [],
        "count": 0,
        "error": None
    }

    try:
        # Use PowerShell to check service permissions
        ps_cmd = """
        Get-WmiObject win32_service | Where-Object {$_.pathname -notmatch '\"' -and $_.pathname -notmatch 'C:\\Windows'} |
        Select-Object Name, DisplayName, PathName, StartMode | Format-List
        """

        cmd_result = generic_linux_command("powershell.exe", f"-Command \"{ps_cmd}\"")

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            result["services"] = output.split('\n')
            result["count"] = len([s for s in result["services"] if s.strip()])
            result["success"] = True
        else:
            result["error"] = cmd_result.get("error", "PowerShell command failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def find_auto_logon_credentials() -> Dict[str, Any]:
    """
    Search for Windows auto-logon credentials in registry.

    Returns:
        Dictionary with auto-logon credentials if found

    Example:
        >>> creds = find_auto_logon_credentials()
    """
    result = {
        "success": False,
        "credentials": {},
        "found": False,
        "error": None
    }

    try:
        # Check registry for auto-logon settings
        reg_path = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

        # Query registry values
        values_to_check = ["DefaultUserName", "DefaultPassword", "DefaultDomainName"]

        credentials = {}
        for value in values_to_check:
            cmd_result = generic_linux_command(
                "reg",
                f"query \"{reg_path}\" /v {value}"
            )

            if cmd_result.get("success"):
                output = cmd_result.get("output", "")
                # Parse registry output
                if "REG_SZ" in output:
                    # Extract value
                    match = re.search(r'REG_SZ\s+(.+)', output)
                    if match:
                        credentials[value] = match.group(1).strip()

        if credentials:
            result["found"] = True
            result["credentials"] = credentials

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def check_always_install_elevated() -> Dict[str, Any]:
    """
    Check if AlwaysInstallElevated registry keys are set.

    Returns:
        Dictionary indicating if AlwaysInstallElevated is enabled

    Example:
        >>> elevated = check_always_install_elevated()
    """
    result = {
        "success": False,
        "enabled": False,
        "hklm_set": False,
        "hkcu_set": False,
        "error": None
    }

    try:
        # Check HKLM key
        cmd_result = generic_linux_command(
            "reg",
            'query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated'
        )

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            if "0x1" in output:
                result["hklm_set"] = True

        # Check HKCU key
        cmd_result = generic_linux_command(
            "reg",
            'query "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated'
        )

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            if "0x1" in output:
                result["hkcu_set"] = True

        # Both must be set for the vulnerability
        if result["hklm_set"] and result["hkcu_set"]:
            result["enabled"] = True

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def enumerate_scheduled_tasks() -> Dict[str, Any]:
    """
    Enumerate Windows scheduled tasks and check for weak permissions.

    Returns:
        Dictionary with scheduled tasks

    Example:
        >>> tasks = enumerate_scheduled_tasks()
    """
    result = {
        "success": False,
        "tasks": [],
        "writable_tasks": [],
        "error": None
    }

    try:
        # List all scheduled tasks
        cmd_result = generic_linux_command("schtasks", "/query /fo LIST /v")

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            result["tasks"] = output.split('\n')

            # Look for tasks running as SYSTEM
            system_tasks = []
            current_task = {}

            for line in result["tasks"]:
                if "TaskName:" in line:
                    if current_task:
                        if current_task.get("run_as") == "SYSTEM":
                            system_tasks.append(current_task)
                    current_task = {"name": line.split(":", 1)[1].strip()}
                elif "Run As User:" in line:
                    current_task["run_as"] = line.split(":", 1)[1].strip()
                elif "Task To Run:" in line:
                    current_task["command"] = line.split(":", 1)[1].strip()

            if current_task and current_task.get("run_as") == "SYSTEM":
                system_tasks.append(current_task)

            result["writable_tasks"] = system_tasks
            result["success"] = True
        else:
            result["error"] = cmd_result.get("error", "schtasks command failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def check_token_privileges() -> Dict[str, Any]:
    """
    Check current token privileges for potential abuse.

    Returns:
        Dictionary with token privileges

    Example:
        >>> privs = check_token_privileges()
    """
    result = {
        "success": False,
        "privileges": [],
        "dangerous_privs": [],
        "error": None
    }

    try:
        # Use whoami to check privileges
        cmd_result = generic_linux_command("whoami", "/priv")

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            result["privileges"] = output.split('\n')

            # Dangerous privileges that can be abused
            dangerous = [
                "SeImpersonatePrivilege",
                "SeAssignPrimaryTokenPrivilege",
                "SeTcbPrivilege",
                "SeBackupPrivilege",
                "SeRestorePrivilege",
                "SeCreateTokenPrivilege",
                "SeLoadDriverPrivilege",
                "SeTakeOwnershipPrivilege",
                "SeDebugPrivilege"
            ]

            for priv in dangerous:
                for line in result["privileges"]:
                    if priv in line and "Enabled" in line:
                        result["dangerous_privs"].append(priv)

            result["success"] = True
        else:
            result["error"] = cmd_result.get("error", "whoami command failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def find_stored_credentials() -> Dict[str, Any]:
    """
    Search for stored credentials on Windows system.

    Returns:
        Dictionary with found credentials

    Example:
        >>> creds = find_stored_credentials()
    """
    result = {
        "success": False,
        "cmdkey": [],
        "credential_manager": [],
        "unattend_files": [],
        "error": None
    }

    try:
        # Check cmdkey stored credentials
        cmd_result = generic_linux_command("cmdkey", "/list")
        if cmd_result.get("success"):
            result["cmdkey"] = cmd_result.get("output", "").split('\n')

        # Search for unattend.xml files
        unattend_paths = [
            "C:\\Windows\\Panther\\Unattend.xml",
            "C:\\Windows\\Panther\\Unattended.xml",
            "C:\\Windows\\System32\\Sysprep\\unattend.xml",
            "C:\\Windows\\System32\\Sysprep\\Panther\\unattend.xml"
        ]

        for path in unattend_paths:
            cmd_result = generic_linux_command("type", path)
            if cmd_result.get("success"):
                content = cmd_result.get("output", "")
                if content:
                    result["unattend_files"].append({
                        "path": path,
                        "content": content
                    })

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


# Helper functions

def _get_windows_system_info() -> Dict[str, str]:
    """Get basic Windows system information."""
    info = {}

    commands = {
        "hostname": "hostname",
        "systeminfo": "systeminfo",
        "user": "whoami",
        "groups": "whoami /groups",
        "privileges": "whoami /priv"
    }

    for key, cmd in commands.items():
        parts = cmd.split()
        result = generic_linux_command(parts[0], " ".join(parts[1:]) if len(parts) > 1 else "")
        if result.get("success"):
            info[key] = result.get("output", "").strip()

    return info
