"""WIN-1.3 — Print Spooler service stopped on Domain Controllers (PrintNightmare).

CVE-2021-34527 / CVE-2021-1675 (PrintNightmare): an authenticated user can
load arbitrary DLLs via the Print Spooler service. The mitigation strongly
recommended by Microsoft is to disable Print Spooler entirely on Domain
Controllers (DCs should never need to print).

For non-DC hosts this check is N/A.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _DcPrintSpoolerCheck:
    control_id = "WIN-1.3"
    control_title = "Print Spooler service stopped on Domain Controllers (PrintNightmare)"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "On every Domain Controller:\n"
        "  Stop-Service Spooler -Force\n"
        "  Set-Service Spooler -StartupType Disabled\n"
        "Or enforce via GPO targeted to the Domain Controllers OU:\n"
        "  Computer Config → Windows Settings → Security Settings → System Services\n"
        "    Print Spooler: Disabled\n"
        "DCs don't print. Leaving the service running keeps the host\n"
        "exposed to CVE-2021-34527 (PrintNightmare) and the older\n"
        "CVE-2010-2729 stuxnet variant. Apply also the LDAP signing +\n"
        "RestrictDriverInstallationToAdministrators=1 hardening alongside\n"
        "any patches."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        # First detect if this is a DC — Get-ADDomainController works only
        # when the host IS a DC (otherwise it queries AD remotely or errors
        # out). The compact form below uses the ProductType registry key:
        # 2 = Domain Controller, 1 = Workstation, 3 = Member Server.
        cmd = (
            'powershell -nop -c "'
            "$pt = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions').ProductType;"
            "$svc = (Get-Service Spooler -ErrorAction SilentlyContinue).Status;"
            'Write-Output "ProductType=$pt SpoolerStatus=$svc"'
            '"'
        )
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="winrm/powershell call failed")

        # Parse "ProductType=LanmanNT SpoolerStatus=Running"
        # ProductType values: WinNT (workstation), LanmanNT (DC), ServerNT (member server).
        product = ""
        spooler = ""
        for tok in out.split():
            if tok.startswith("ProductType="):
                product = tok.split("=", 1)[1].strip()
            elif tok.startswith("SpoolerStatus="):
                spooler = tok.split("=", 1)[1].strip()

        if product != "LanmanNT":
            return make_result(
                check=self,
                verdict="N/A",
                cmd=cmd,
                out=out,
                err=err,
                parsed={"product_type": product or "unknown", "reason": "not a Domain Controller"},
                t0=t0,
                ctx=ctx,
            )

        # DC confirmed — check spooler state.
        if spooler.lower() == "running":
            verdict, parsed = "FAIL", {"product_type": product, "spooler_status": spooler}
        elif spooler.lower() in ("stopped", ""):
            verdict, parsed = "PASS", {"product_type": product, "spooler_status": spooler or "disabled/not installed"}
        else:
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason=f"unexpected spooler state: {spooler!r}"
            )
        return make_result(check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed=parsed, t0=t0, ctx=ctx)


CHECK = _DcPrintSpoolerCheck()
register_check(CHECK)
