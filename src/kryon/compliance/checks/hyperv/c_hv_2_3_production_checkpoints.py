"""HV-2.3 — VMs use Production checkpoints (not Standard).

CIS Hyper-V Benchmark: a Standard checkpoint saves the VM's live memory to a
.vmrs file on disk — that RAM image can contain credentials, keys and PII,
sitting unencrypted at rest. Production checkpoints use VSS (application-
consistent, no memory dump), so they don't leak guest secrets.

FAIL if any VM has CheckpointType = Standard. ERROR if not a Hyper-V host.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _ProductionCheckpointsCheck:
    control_id = "HV-2.3"
    control_title = "VMs use Production checkpoints (not Standard)"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Switch VMs to production checkpoints (PowerShell, admin):\n"
        "  Get-VM | Set-VM -CheckpointType Production\n"
        "Use ProductionOnly to forbid falling back to Standard."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "@(Get-VM | '
            "Where-Object CheckpointType -eq 'Standard' | ForEach-Object Name) -join ','\""
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
            parsed={"vms_with_standard_checkpoints": offenders},
            t0=t0,
            ctx=ctx,
        )


CHECK = _ProductionCheckpointsCheck()
register_check(CHECK)
