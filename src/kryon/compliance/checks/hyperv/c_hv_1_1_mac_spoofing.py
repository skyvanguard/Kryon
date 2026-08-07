"""HV-1.1 — VM MAC address spoofing disabled.

CIS Hyper-V Benchmark: MacAddressSpoofing 'On' lets a guest send frames with
arbitrary source MACs — MAC-flooding, ARP poisoning and impersonation of
other VMs on the same switch. It must be 'Off' (the default) unless a VM
legitimately needs it (nested virt / NLB).

FAIL if any VM adapter has MacAddressSpoofing = On. ERROR if this is not a
Hyper-V host / the WinRM call fails.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _MacSpoofCheck:
    control_id = "HV-1.1"
    control_title = "VM MAC address spoofing disabled"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Disable MAC spoofing on VM adapters (PowerShell, admin):\n"
        "  Get-VMNetworkAdapter -All | Set-VMNetworkAdapter -MacAddressSpoofing Off\n"
        "Enable only where required (nested virtualization / NLB)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "@(Get-VMNetworkAdapter -All | '
            "Where-Object MacAddressSpoofing -eq 'On' | ForEach-Object VMName) -join ','\""
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
            parsed={"vms_with_mac_spoofing": offenders},
            t0=t0,
            ctx=ctx,
        )


CHECK = _MacSpoofCheck()
register_check(CHECK)
