"""HV-3.2 — Nested virtualization disabled unless required.

Exposing virtualization extensions (`ExposeVirtualizationExtensions`) lets a
guest run its own hypervisor — expanding the attack surface and enabling a
guest to spin up unmonitored nested VMs. It should be off except for
sanctioned workloads (CI runners, WSL2-in-VM, dev labs).

FAIL if any VM has virtualization extensions exposed. ERROR if not a
Hyper-V host.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _NestedVirtCheck:
    control_id = "HV-3.2"
    control_title = "Nested virtualization disabled unless required"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Disable nested virtualization on VMs that don't need it (admin):\n"
        "  Get-VM <vm> | Set-VMProcessor -ExposeVirtualizationExtensions $false\n"
        "Requires the VM to be off. Leave on only for sanctioned nested workloads."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "@(Get-VM | Get-VMProcessor | '
            "Where-Object ExposeVirtualizationExtensions -eq $true | ForEach-Object VMName) -join ','\""
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
            parsed={"vms_with_nested_virt": offenders},
            t0=t0,
            ctx=ctx,
        )


CHECK = _NestedVirtCheck()
register_check(CHECK)
