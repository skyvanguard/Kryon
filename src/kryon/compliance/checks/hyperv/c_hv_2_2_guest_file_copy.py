"""HV-2.2 — Guest file-copy integration service disabled.

CIS Hyper-V Benchmark: the "Guest Service Interface" integration service lets
the host push files into a running guest with `Copy-VMFile` — a host->guest
lateral-movement / malware-injection path. It should be disabled unless a
specific workflow needs it.

FAIL if any VM has the Guest Service Interface enabled. ERROR if not a
Hyper-V host.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _GuestFileCopyCheck:
    control_id = "HV-2.2"
    control_title = "Guest file-copy integration service disabled"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Disable the guest file-copy service (PowerShell, admin):\n"
        "  Get-VM | Disable-VMIntegrationService -Name 'Guest Service Interface'\n"
        "Re-enable only for the specific VM + window that needs Copy-VMFile."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "@(Get-VM | '
            "Get-VMIntegrationService -Name 'Guest Service Interface' | "
            "Where-Object Enabled -eq $true | ForEach-Object VMName) -join ','\""
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
            parsed={"vms_with_guest_file_copy": offenders},
            t0=t0,
            ctx=ctx,
        )


CHECK = _GuestFileCopyCheck()
register_check(CHECK)
