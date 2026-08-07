"""HV-3.1 — Live Migration authentication uses Kerberos (not CredSSP).

CIS Hyper-V Benchmark: with CredSSP the admin's credentials are delegated to
the target host (constrained-delegation / credential-theft risk) and it can't
be used unattended. Kerberos (constrained delegation) is the secure choice.

FAIL if VirtualMachineMigrationAuthenticationType is CredSSP. ERROR if not a
Hyper-V host.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _MigrationAuthCheck:
    control_id = "HV-3.1"
    control_title = "Live Migration authentication uses Kerberos"
    section = "3"
    severity = "HIGH"
    remediation_static = (
        "Use Kerberos for Live Migration (PowerShell, admin):\n"
        "  Set-VMHost -VirtualMachineMigrationAuthenticationType Kerberos\n"
        "Configure constrained delegation for the Migration + CIFS services on\n"
        "each host in AD."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = 'powershell -nop -c "(Get-VMHost).VirtualMachineMigrationAuthenticationType"'
        out, err, rc = run_cmd(ctx, cmd, timeout_s=20)
        if rc != 0 and not out.strip():
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed (Hyper-V host?)"
            )

        value = out.strip().splitlines()[-1].strip() if out.strip() else ""
        verdict = "FAIL" if value.lower() == "credssp" else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"migration_auth_type": value or "(unknown)"},
            t0=t0,
            ctx=ctx,
        )


CHECK = _MigrationAuthCheck()
register_check(CHECK)
