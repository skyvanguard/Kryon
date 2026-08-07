"""WIN-2.3 — BitLocker encryption enabled on the system drive."""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _BitLockerCheck:
    control_id = "WIN-2.3"
    control_title = "BitLocker encryption enabled on the system drive"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Enable BitLocker on the system drive (TPM required for unattended boot):\n"
        "  Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly\n"
        "Back up the recovery key to AD / Azure AD:\n"
        "  Backup-BitLockerKeyProtector -MountPoint 'C:' -KeyProtectorId <id>\n"
        "Enforce via GPO at Computer Config → Admin Templates → Windows Components →\n"
        "BitLocker Drive Encryption → Operating System Drives.\n"
        "Without disk encryption a stolen laptop / decommissioned drive can\n"
        "be mounted in another OS to read all data offline."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = 'powershell -nop -c "(Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue).ProtectionStatus"'
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out and "ParameterBindingValidationException" not in err:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        value = out.strip()
        # ProtectionStatus enum: 0 = Off, 1 = On, 2 = Unknown.
        if value == "1" or value.lower().endswith("on"):
            verdict, parsed = "PASS", {"protection_status": "On"}
        elif value == "0" or value.lower().endswith("off") or not value:
            verdict, parsed = "FAIL", {"protection_status": value or "Off (no BitLocker volume on C:)"}
        else:
            verdict, parsed = "FAIL", {"protection_status": value}
        return make_result(check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed=parsed, t0=t0, ctx=ctx)


CHECK = _BitLockerCheck()
register_check(CHECK)
