"""HV-2.4 — Automatic checkpoints disabled on production VMs.

Automatic checkpoints (on by default on client/dev Hyper-V) snapshot a VM
when it starts. On production servers they accumulate silently, consume
storage, and — if Standard-type — leave memory images on disk. They should
be disabled on server workloads.

FAIL if any VM has AutomaticCheckpointsEnabled = True. ERROR if not a
Hyper-V host.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _AutomaticCheckpointsCheck:
    control_id = "HV-2.4"
    control_title = "Automatic checkpoints disabled on production VMs"
    section = "2"
    severity = "LOW"
    remediation_static = (
        "Disable automatic checkpoints (PowerShell, admin):\n  Get-VM | Set-VM -AutomaticCheckpointsEnabled $false"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "@(Get-VM | '
            "Where-Object AutomaticCheckpointsEnabled -eq $true | ForEach-Object Name) -join ','\""
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
            parsed={"vms_with_automatic_checkpoints": offenders},
            t0=t0,
            ctx=ctx,
        )


CHECK = _AutomaticCheckpointsCheck()
register_check(CHECK)
