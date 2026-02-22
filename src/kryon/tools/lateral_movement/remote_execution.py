"""
KRYON Remote Execution Module
===============================

Remote command execution tools for lateral movement.
Implements PsExec, WMI, SMB, DCOM, SSH, and WinRM execution.

Primary Users:
- Pentest Agent (Alpha-Red)
- Network Analyst (Alpha-Silver)
"""

from typing import Any, Optional

from kryon.tools.common import generic_linux_command


def psexec_execute(
    target: str,
    username: str,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    domain: Optional[str] = ".",
    command: str = "whoami",
) -> dict[str, Any]:
    """
    Execute command via PsExec-style SMB execution.

    Args:
        target: Target IP or hostname
        username: Username
        password: Password (or use ntlm_hash)
        ntlm_hash: NTLM hash for PTH
        domain: Domain name
        command: Command to execute

    Returns:
        Dictionary with execution result

    Example:
        >>> result = psexec_execute(
        ...     target="192.168.1.100",
        ...     username="admin",
        ...     password="P@ssw0rd",
        ...     command="whoami"
        ... )
    """
    result = {"success": False, "output": "", "error": None}

    try:
        cmd_parts = ["psexec.py"]

        # Authentication
        if ntlm_hash:
            cmd_parts.append(f"{domain}/{username}@{target}")
            cmd_parts.extend(["-hashes", ntlm_hash])
        elif password:
            cmd_parts.append(f"{domain}/{username}:{password}@{target}")
        else:
            result["error"] = "Password or NTLM hash required"
            return result

        cmd_parts.append(command)

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = cmd_result.get("output", "")
        else:
            result["error"] = cmd_result.get("error", "PsExec failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def wmiexec_execute(
    target: str,
    username: str,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    domain: Optional[str] = ".",
    command: str = "whoami",
) -> dict[str, Any]:
    """Execute command via WMI."""
    result = {"success": False, "output": "", "error": None}

    try:
        cmd_parts = ["wmiexec.py"]

        if ntlm_hash:
            cmd_parts.append(f"{domain}/{username}@{target}")
            cmd_parts.extend(["-hashes", ntlm_hash])
        elif password:
            cmd_parts.append(f"{domain}/{username}:{password}@{target}")

        cmd_parts.append(command)

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = cmd_result.get("output", "")
        else:
            result["error"] = cmd_result.get("error", "WMI execution failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def smbexec_execute(
    target: str,
    username: str,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    domain: Optional[str] = ".",
    command: str = "whoami",
) -> dict[str, Any]:
    """Execute command via SMB."""
    result = {"success": False, "output": "", "error": None}

    try:
        cmd_parts = ["smbexec.py"]

        if ntlm_hash:
            cmd_parts.append(f"{domain}/{username}@{target}")
            cmd_parts.extend(["-hashes", ntlm_hash])
        elif password:
            cmd_parts.append(f"{domain}/{username}:{password}@{target}")

        cmd_parts.append(command)

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = cmd_result.get("output", "")
        else:
            result["error"] = cmd_result.get("error", "SMB execution failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def dcomexec_execute(
    target: str,
    username: str,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    domain: Optional[str] = ".",
    command: str = "whoami",
    object_type: str = "MMC20",
) -> dict[str, Any]:
    """Execute command via DCOM."""
    result = {"success": False, "output": "", "error": None}

    try:
        cmd_parts = ["dcomexec.py"]

        if ntlm_hash:
            cmd_parts.append(f"{domain}/{username}@{target}")
            cmd_parts.extend(["-hashes", ntlm_hash])
        elif password:
            cmd_parts.append(f"{domain}/{username}:{password}@{target}")

        cmd_parts.extend(["-object", object_type])
        cmd_parts.append(command)

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = cmd_result.get("output", "")
        else:
            result["error"] = cmd_result.get("error", "DCOM execution failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def ssh_execute(
    target: str,
    username: str,
    password: Optional[str] = None,
    key_file: Optional[str] = None,
    command: str = "whoami",
    port: int = 22,
) -> dict[str, Any]:
    """Execute command via SSH."""
    result = {"success": False, "output": "", "error": None}

    try:
        cmd_parts = ["ssh"]

        if key_file:
            cmd_parts.extend(["-i", key_file])
        if port != 22:
            cmd_parts.extend(["-p", str(port)])

        cmd_parts.append(f"{username}@{target}")
        cmd_parts.append(command)

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = cmd_result.get("output", "")
        else:
            result["error"] = cmd_result.get("error", "SSH execution failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def winrm_execute(
    target: str,
    username: str,
    password: str,
    domain: Optional[str] = ".",
    command: str = "whoami",
    port: int = 5985,
    ssl: bool = False,
) -> dict[str, Any]:
    """Execute command via WinRM."""
    result = {"success": False, "output": "", "error": None}

    try:
        cmd_parts = ["evil-winrm"]
        cmd_parts.extend(["-i", target])
        cmd_parts.extend(["-u", username])
        cmd_parts.extend(["-p", password])

        if port != 5985:
            cmd_parts.extend(["-P", str(port)])
        if ssl:
            cmd_parts.append("-S")

        cmd_parts.extend(["-c", command])

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = cmd_result.get("output", "")
        else:
            result["error"] = cmd_result.get("error", "WinRM execution failed")

    except Exception as e:
        result["error"] = str(e)

    return result
