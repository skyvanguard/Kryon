"""HV-1.2 — VM automatic stop action is not TurnOff.

CIS Hyper-V Benchmark: `AutomaticStopAction = TurnOff` hard-powers-off guests
when the host shuts down — risking filesystem/DB corruption. VMs should Save
(preserve state) or ShutDown (clean guest shutdown via integration services).

FAIL if any VM has AutomaticStopAction = TurnOff. ERROR if not a Hyper-V host.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _AutomaticStopCheck:
    control_id = "HV-1.2"
    control_title = "VM automatic stop action is not TurnOff"
    section = "1"
    severity = "LOW"
    remediation_static = (
        "Set a safe stop action per VM (PowerShell, admin):\n"
        "  Get-VM | Set-VM -AutomaticStopAction Save\n"
        "Use ShutDown where integration services provide a clean guest shutdown."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "@(Get-VM | '
            "Where-Object AutomaticStopAction -eq 'TurnOff' | ForEach-Object Name) -join ','\""
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=20)
        if rc != 0 and not out.strip():
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed (Hyper-V host?)"
            )

        offenders = [v.strip() for v in out.strip().split(",") if v.strip()]
        verdict = "FAIL" if offenders else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"vms_turnoff_on_host_stop": offenders},
            t0=t0,
            ctx=ctx,
        )


CHECK = _AutomaticStopCheck()
register_check(CHECK)
