"""Shared helpers for Microsoft IIS checks.

Read server-wide settings from applicationHost.config via the WebAdministration
module over WinRM (same transport as the Windows Server audit; set
ctx.transport = "winrm"). Reading MACHINE/WEBROOT/APPHOST gives the effective
server default, not a single site.
"""

from __future__ import annotations

from kryon.compliance.checks.windows._common import make_error, make_result  # noqa: F401 — re-export


def webconfig(filter_path: str, name: str) -> str:
    """PowerShell to read one IIS config property's effective value."""
    return (
        'powershell -nop -c "Import-Module WebAdministration -ErrorAction SilentlyContinue; '
        f"(Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' "
        f"-filter '{filter_path}' -name '{name}').Value\""
    )


def last_value(out: str) -> str:
    """Last non-empty line of PowerShell output (the property value)."""
    for line in reversed(out.splitlines()):
        if line.strip():
            return line.strip()
    return ""
