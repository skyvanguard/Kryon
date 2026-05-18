"""WIN-4.1 — Remote Registry service stopped + disabled."""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _RemoteRegistryCheck:
    control_id = "WIN-4.1"
    control_title = "Remote Registry service stopped and set to Disabled"
    section = "4"
    severity = "LOW"
    remediation_static = (
        "Stop and disable the Remote Registry service:\n"
        "  Stop-Service RemoteRegistry -Force\n"
        "  Set-Service RemoteRegistry -StartupType Disabled\n"
        "Or GPO:\n"
        "  Computer Config → Windows Settings → Security Settings → System Services\n"
        "    Remote Registry: Disabled\n"
        "Remote Registry is rarely needed in production; leaving it running\n"
        "gives anyone with valid creds a low-friction enumeration vector\n"
        "(reg query of HKLM remotely from a non-admin tool)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "'
            "$svc = Get-Service RemoteRegistry -ErrorAction SilentlyContinue;"
            'if ($svc) { Write-Output "Status=$($svc.Status) StartType=$($svc.StartType)" } '
            "else { Write-Output 'NotInstalled' }"
            '"'
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        text = out.strip()
        if text == "NotInstalled":
            return make_result(
                check=self,
                verdict="PASS",
                cmd=cmd,
                out=out,
                err=err,
                parsed={"reason": "service not installed"},
                t0=t0,
                ctx=ctx,
            )

        running = "Status=Running" in text
        startup_disabled = "StartType=Disabled" in text
        if running:
            verdict = "FAIL"
        elif not startup_disabled:
            # Stopped but auto-start enabled — still a fail (any boot will revive it).
            verdict = "FAIL"
        else:
            verdict = "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"raw": text, "running": running, "startup_disabled": startup_disabled},
            t0=t0,
            ctx=ctx,
        )


CHECK = _RemoteRegistryCheck()
register_check(CHECK)
