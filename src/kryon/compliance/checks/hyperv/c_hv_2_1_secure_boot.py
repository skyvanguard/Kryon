"""HV-2.1 — Secure Boot enabled on Generation-2 VMs.

CIS Hyper-V Benchmark: Gen2 VMs support UEFI Secure Boot, which blocks
unsigned/tampered bootloaders and rootkits. It should be On. (Gen1 VMs have
no firmware object and are skipped.)

FAIL if any Gen2 VM has SecureBoot = Off. ERROR if not a Hyper-V host.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _SecureBootCheck:
    control_id = "HV-2.1"
    control_title = "Secure Boot enabled on Generation-2 VMs"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Enable Secure Boot on Gen2 VMs (PowerShell, admin):\n"
        "  Set-VMFirmware -VMName <vm> -EnableSecureBoot On\n"
        "Use the MicrosoftWindows or MicrosoftUEFICertificateAuthority template as\n"
        "appropriate for the guest OS. Requires the VM to be off."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "@(Get-VM | Get-VMFirmware -ErrorAction SilentlyContinue | '
            "Where-Object SecureBoot -eq 'Off' | ForEach-Object VMName) -join ','\""
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
            parsed={"gen2_vms_secureboot_off": offenders},
            t0=t0,
            ctx=ctx,
        )


CHECK = _SecureBootCheck()
register_check(CHECK)
