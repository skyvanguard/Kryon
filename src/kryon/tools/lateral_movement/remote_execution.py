"""
KRYON Remote Execution Module
===============================

Remote command execution tools for lateral movement.
Implements PsExec, WMI, SMB, DCOM, SSH, and WinRM execution.

Primary Users:
- Pentest Agent (Alpha-Red)
- Network Analyst (Alpha-Silver)

Authorization: red-team gated (KRYON_RED_TEAM). Only use within an authorized
penetration-testing scope with written authorization.
"""

import json

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command

# Markers that mean the tool failed (its output is an error, not a result).
_FAIL_MARKERS = (
    "error",
    "failed",
    "denied",
    "not found",
    "no such",
    "traceback",
    "refused",
    "not installed",
    "command not found",
    "usage:",
)


def _exec(cmd_parts: list[str]) -> tuple[bool, str]:
    """Run cmd_parts and return (success, output).

    T4-M10: ``run_command`` returns a STRING and its 2nd positional is ``interactive``
    (not args), so the old ``run_command(cmd_parts[0], " ".join(cmd_parts[1:]))`` ran
    only the bare binary and then did ``str.get(...)`` — an AttributeError swallowed by
    the except, so every call returned a fake failure. Join the whole command and
    interpret the returned string (same fix as pth_attacks T4-C1).
    """
    out = run_command(" ".join(cmd_parts))
    low = (out or "").lower()
    ok = bool(out.strip()) and not any(m in low for m in _FAIL_MARKERS)
    return ok, out


@function_tool(strict_mode=False)
def psexec_execute(
    target: str,
    username: str,
    password: str | None = None,
    ntlm_hash: str | None = None,
    domain: str | None = ".",
    command: str = "whoami",
) -> str:
    """
    Execute a command on a remote Windows host via PsExec-style SMB service
    execution (impacket ``psexec.py``). Supports pass-the-hash with an NTLM hash
    or plaintext-password authentication.

    Args:
        target: Target IP or hostname
        username: Username to authenticate as
        password: Password (or use ntlm_hash)
        ntlm_hash: NTLM hash for pass-the-hash (LM:NT)
        domain: Domain name (default "." for local)
        command: Command to execute (default whoami)

    Returns:
        str: JSON with success status, output, and error.
    """
    result = {"success": False, "output": "", "error": None}

    cmd_parts = ["psexec.py"]
    if ntlm_hash:
        cmd_parts.append(f"{domain}/{username}@{target}")
        cmd_parts.extend(["-hashes", ntlm_hash])
    elif password:
        cmd_parts.append(f"{domain}/{username}:{password}@{target}")
    else:
        result["error"] = "Password or NTLM hash required"
        return json.dumps(result)

    cmd_parts.append(command)

    ok, out = _exec(cmd_parts)
    if ok:
        result["success"] = True
        result["output"] = out
    else:
        result["error"] = out.strip() or "PsExec failed"
    return json.dumps(result)


@function_tool(strict_mode=False)
def wmiexec_execute(
    target: str,
    username: str,
    password: str | None = None,
    ntlm_hash: str | None = None,
    domain: str | None = ".",
    command: str = "whoami",
) -> str:
    """Execute a command on a remote Windows host via WMI (impacket ``wmiexec.py``).
    Pass-the-hash or password auth. Returns JSON {success, output, error}."""
    result = {"success": False, "output": "", "error": None}

    cmd_parts = ["wmiexec.py"]
    if ntlm_hash:
        cmd_parts.append(f"{domain}/{username}@{target}")
        cmd_parts.extend(["-hashes", ntlm_hash])
    elif password:
        cmd_parts.append(f"{domain}/{username}:{password}@{target}")
    else:
        result["error"] = "Password or NTLM hash required"
        return json.dumps(result)

    cmd_parts.append(command)

    ok, out = _exec(cmd_parts)
    if ok:
        result["success"] = True
        result["output"] = out
    else:
        result["error"] = out.strip() or "WMI execution failed"
    return json.dumps(result)


@function_tool(strict_mode=False)
def smbexec_execute(
    target: str,
    username: str,
    password: str | None = None,
    ntlm_hash: str | None = None,
    domain: str | None = ".",
    command: str = "whoami",
) -> str:
    """Execute a command on a remote Windows host via SMB (impacket ``smbexec.py``).
    Pass-the-hash or password auth. Returns JSON {success, output, error}."""
    result = {"success": False, "output": "", "error": None}

    cmd_parts = ["smbexec.py"]
    if ntlm_hash:
        cmd_parts.append(f"{domain}/{username}@{target}")
        cmd_parts.extend(["-hashes", ntlm_hash])
    elif password:
        cmd_parts.append(f"{domain}/{username}:{password}@{target}")
    else:
        result["error"] = "Password or NTLM hash required"
        return json.dumps(result)

    cmd_parts.append(command)

    ok, out = _exec(cmd_parts)
    if ok:
        result["success"] = True
        result["output"] = out
    else:
        result["error"] = out.strip() or "SMB execution failed"
    return json.dumps(result)


@function_tool(strict_mode=False)
def dcomexec_execute(
    target: str,
    username: str,
    password: str | None = None,
    ntlm_hash: str | None = None,
    domain: str | None = ".",
    command: str = "whoami",
    object_type: str = "MMC20",
) -> str:
    """Execute a command on a remote Windows host via DCOM (impacket ``dcomexec.py``).
    ``object_type`` selects the DCOM object (MMC20, ShellWindows, ShellBrowserWindow).
    Pass-the-hash or password auth. Returns JSON {success, output, error}."""
    result = {"success": False, "output": "", "error": None}

    cmd_parts = ["dcomexec.py"]
    if ntlm_hash:
        cmd_parts.append(f"{domain}/{username}@{target}")
        cmd_parts.extend(["-hashes", ntlm_hash])
    elif password:
        cmd_parts.append(f"{domain}/{username}:{password}@{target}")
    else:
        result["error"] = "Password or NTLM hash required"
        return json.dumps(result)

    cmd_parts.extend(["-object", object_type])
    cmd_parts.append(command)

    ok, out = _exec(cmd_parts)
    if ok:
        result["success"] = True
        result["output"] = out
    else:
        result["error"] = out.strip() or "DCOM execution failed"
    return json.dumps(result)


@function_tool(strict_mode=False)
def ssh_execute(
    target: str,
    username: str,
    password: str | None = None,
    key_file: str | None = None,
    command: str = "whoami",
    port: int = 22,
) -> str:
    """Execute a command on a remote host via SSH. Key-file auth when ``key_file`` is
    given (BatchMode); otherwise relies on an agent/known credentials. Returns JSON
    {success, output, error}."""
    result = {"success": False, "output": "", "error": None}

    cmd_parts = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no"]
    if key_file:
        cmd_parts.extend(["-i", key_file])
    if port != 22:
        cmd_parts.extend(["-p", str(port)])

    cmd_parts.append(f"{username}@{target}")
    cmd_parts.append(command)

    ok, out = _exec(cmd_parts)
    if ok:
        result["success"] = True
        result["output"] = out
    else:
        result["error"] = out.strip() or "SSH execution failed"
    return json.dumps(result)


@function_tool(strict_mode=False)
def winrm_execute(
    target: str,
    username: str,
    password: str,
    domain: str | None = ".",
    command: str = "whoami",
    port: int = 5985,
    ssl: bool = False,
) -> str:
    """Execute a command on a remote Windows host via WinRM (``evil-winrm``). Returns
    JSON {success, output, error}."""
    result = {"success": False, "output": "", "error": None}

    cmd_parts = ["evil-winrm", "-i", target, "-u", username, "-p", password]
    if port != 5985:
        cmd_parts.extend(["-P", str(port)])
    if ssl:
        cmd_parts.append("-S")

    cmd_parts.extend(["-c", command])

    ok, out = _exec(cmd_parts)
    if ok:
        result["success"] = True
        result["output"] = out
    else:
        result["error"] = out.strip() or "WinRM execution failed"
    return json.dumps(result)
