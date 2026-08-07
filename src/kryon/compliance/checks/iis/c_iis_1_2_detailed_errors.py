"""IIS-1.2 — Detailed errors not sent to remote clients.

CIS IIS Benchmark: httpErrors errorMode `Detailed` returns full error pages
(paths, stack context) to every client. It must be `DetailedLocalOnly` (the
default) or `Custom` so remote users only get generic errors.

FAIL if errorMode is Detailed. PASS otherwise. ERROR if IIS/WinRM can't be
queried.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.iis._common import last_value, make_error, make_result, webconfig
from kryon.compliance.runner import register_check, run_cmd


class _DetailedErrorsCheck:
    control_id = "IIS-1.2"
    control_title = "Detailed errors not sent to remote clients"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        "Set errorMode server-wide (PowerShell, admin):\n"
        "  Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' "
        "-filter 'system.webServer/httpErrors' -name errorMode -value DetailedLocalOnly"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = webconfig("system.webServer/httpErrors", "errorMode")
        out, err, rc = run_cmd(ctx, cmd, timeout_s=25)
        value = last_value(out)
        if not value:
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="WinRM/IIS query failed (IIS host?)"
            )

        verdict = "FAIL" if value.lower() == "detailed" else "PASS"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"error_mode": value}, t0=t0, ctx=ctx
        )


CHECK = _DetailedErrorsCheck()
register_check(CHECK)
