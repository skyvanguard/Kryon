"""WIN-1.2 — LSA Protection (RunAsPPL) enabled (mitigates Mimikatz / lsass dump)."""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _LsaProtectionCheck:
    control_id = "WIN-1.2"
    control_title = "LSA Protection (RunAsPPL) enabled"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "Enable LSA Protection via registry:\n"
        "  reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f\n"
        "Or GPO:\n"
        "  Computer Config → Admin Templates → System → Local Security Authority →\n"
        "    Configure LSASS to run as a protected process: Enabled\n"
        "Reboot required. Without this setting, LSASS memory can be dumped by\n"
        "Mimikatz/SekurLSA to extract NTLM hashes and Kerberos tickets in\n"
        "cleartext from any local Administrator session."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            'powershell -nop -c "(Get-ItemProperty '
            "-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
            '-Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL"'
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out and "ItemNotFound" not in err:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        value = out.strip()
        if value in ("1", "2"):  # 1 = PPL, 2 = PPL with audit (also acceptable)
            verdict, parsed = "PASS", {"RunAsPPL": int(value)}
        else:
            # Missing key or 0 = unprotected.
            verdict, parsed = "FAIL", {"RunAsPPL": value or "absent"}
        return make_result(check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed=parsed, t0=t0, ctx=ctx)


CHECK = _LsaProtectionCheck()
register_check(CHECK)
