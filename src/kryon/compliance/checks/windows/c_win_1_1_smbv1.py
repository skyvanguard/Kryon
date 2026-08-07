"""WIN-1.1 — SMBv1 protocol disabled (CVE-2017-0144 EternalBlue mitigations)."""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _Smbv1Check:
    control_id = "WIN-1.1"
    control_title = "SMBv1 protocol disabled"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "Disable SMBv1 via PowerShell (admin):\n"
        "  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
        "Then enforce via GPO:\n"
        "  Computer Config → Admin Templates → MS Security Guide →\n"
        "    Configure SMB v1 server: Disabled\n"
        "    Configure SMB v1 client driver: Disable driver\n"
        "Reboot required for the client side. Verify with:\n"
        "  Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\n"
        "See also CVE-2017-0144 (EternalBlue) — SMBv1 is the precondition."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = 'powershell -nop -c "(Get-SmbServerConfiguration).EnableSMB1Protocol"'
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")
        value = out.strip().lower()
        # PowerShell prints "True" or "False" with leading newline.
        if value.endswith("true"):
            verdict, parsed = "FAIL", {"smb1_enabled": True}
        elif value.endswith("false"):
            verdict, parsed = "PASS", {"smb1_enabled": False}
        else:
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason=f"unparseable output: {value[:80]!r}"
            )
        return make_result(check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed=parsed, t0=t0, ctx=ctx)


CHECK = _Smbv1Check()
register_check(CHECK)
