"""
SKYNET Privilege Escalation Tools Module
=========================================

This module provides privilege escalation capabilities for SKYNET agents.
Includes enumeration scripts, exploit suggesters, and automated escalation tools.

Capabilities:
- Linux privilege escalation enumeration (LinPEAS-style)
- Windows privilege escalation enumeration (WinPEAS-style)
- SUID/SGID binary discovery and exploitation
- Kernel exploit suggestions
- Container escape techniques
- Service misconfiguration detection

Agents using this module:
- T-800 Infiltrator (Alpha-Red): Post-exploitation privilege escalation
- T-1000 Advanced Hunter (Omega-Strike): Advanced privilege escalation techniques

Authorization: Only use within authorized penetration testing scope.
"""

from .linux_privesc import (
    enumerate_linux_privesc,
    find_suid_binaries,
    find_writable_files,
    check_sudo_permissions,
    suggest_kernel_exploits,
    check_capabilities,
    find_cron_jobs,
    check_docker_escape,
)

from .windows_privesc import (
    enumerate_windows_privesc,
    find_unquoted_service_paths,
    check_weak_service_permissions,
    find_auto_logon_credentials,
    check_always_install_elevated,
    enumerate_scheduled_tasks,
    check_token_privileges,
    find_stored_credentials,
    # Phase 16: Enhanced Windows Privilege Escalation (January 22, 2025)
    run_winpeas,
    run_powerup,
    check_uac_bypasses,
    harvest_credentials,
    check_token_privileges_enhanced,
)

from .privesc_suggester import (
    suggest_privesc_vectors,
    check_kernel_version,
    analyze_system_for_privesc,
)

__all__ = [
    # Linux Privilege Escalation
    'enumerate_linux_privesc',
    'find_suid_binaries',
    'find_writable_files',
    'check_sudo_permissions',
    'suggest_kernel_exploits',
    'check_capabilities',
    'find_cron_jobs',
    'check_docker_escape',

    # Windows Privilege Escalation
    'enumerate_windows_privesc',
    'find_unquoted_service_paths',
    'check_weak_service_permissions',
    'find_auto_logon_credentials',
    'check_always_install_elevated',
    'enumerate_scheduled_tasks',
    'check_token_privileges',
    'find_stored_credentials',

    # Phase 16: Enhanced Windows Privilege Escalation
    'run_winpeas',
    'run_powerup',
    'check_uac_bypasses',
    'harvest_credentials',
    'check_token_privileges_enhanced',

    # Privilege Escalation Suggester
    'suggest_privesc_vectors',
    'check_kernel_version',
    'analyze_system_for_privesc',
]
