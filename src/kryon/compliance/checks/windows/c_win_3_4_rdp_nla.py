"""WIN-3.4 — RDP requires Network Level Authentication (NLA)."""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _RdpNlaCheck:
    control_id = "WIN-3.4"
    control_title = "RDP requires Network Level Authentication (NLA)"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Enable NLA via registry:\n"
        "  reg add 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' \\\n"
        "    /v UserAuthentication /t REG_DWORD /d 1 /f\n"
        "Or PowerShell:\n"
        "  Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "-Name UserAuthentication -Value 1\n"
        "Or GPO:\n"
        "  Computer Config → Admin Templates → Windows Components → Remote Desktop\n"
        "    Services → Remote Desktop Session Host → Security →\n"
        "    Require user authentication for remote connections by using NLA: Enabled\n"
        "Without NLA the RDP server accepts pre-auth connections; BlueKeep\n"
        "(CVE-2019-0708) and several wormable RCEs targeted this surface."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "(Get-ItemProperty '
            "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
            '-Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication"'
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out and "ItemNotFound" not in err:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        value = out.strip()
        if value == "1":
            verdict, parsed = "PASS", {"UserAuthentication": 1}
        else:
            verdict, parsed = "FAIL", {"UserAuthentication": value or "absent (NLA off)"}
        return make_result(check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed=parsed, t0=t0, ctx=ctx)


CHECK = _RdpNlaCheck()
register_check(CHECK)
