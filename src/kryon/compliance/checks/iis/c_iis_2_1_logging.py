"""IIS-2.1 — HTTP logging enabled.

CIS IIS Benchmark: without request logging there is no record of who accessed
the server — no forensic trail after an incident. The site-default logFile
must be enabled.

FAIL if logging is disabled. PASS if enabled. ERROR if IIS/WinRM can't be
queried.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.iis._common import last_value, make_error, make_result, webconfig
from kryon.compliance.runner import register_check, run_cmd


class _LoggingCheck:
    control_id = "IIS-2.1"
    control_title = "HTTP logging enabled"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Enable logging on the site defaults (PowerShell, admin):\n"
        "  Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' "
        "-filter 'system.applicationHost/sites/siteDefaults/logFile' -name enabled -value True"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = webconfig("system.applicationHost/sites/siteDefaults/logFile", "enabled")
        out, err, rc = run_cmd(ctx, cmd, timeout_s=25)
        value = last_value(out)
        if not value:
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="WinRM/IIS query failed (IIS host?)"
            )

        verdict = "PASS" if value.lower() == "true" else "FAIL"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"logging_enabled": value}, t0=t0, ctx=ctx
        )


CHECK = _LoggingCheck()
register_check(CHECK)
