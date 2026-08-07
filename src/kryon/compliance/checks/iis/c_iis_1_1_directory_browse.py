"""IIS-1.1 — Directory browsing disabled.

CIS IIS Benchmark: directory browsing serves a listing of any folder without a
default document, leaking file names, backups and source. It must be disabled
server-wide.

FAIL if directoryBrowse is enabled. PASS if disabled. ERROR if IIS/WinRM can't
be queried.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.iis._common import last_value, make_error, make_result, webconfig
from kryon.compliance.runner import register_check, run_cmd


class _DirectoryBrowseCheck:
    control_id = "IIS-1.1"
    control_title = "Directory browsing disabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        "Disable server-wide (PowerShell, admin):\n"
        "  Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' "
        "-filter 'system.webServer/directoryBrowse' -name enabled -value False"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = webconfig("system.webServer/directoryBrowse", "enabled")
        out, err, rc = run_cmd(ctx, cmd, timeout_s=25)
        value = last_value(out)
        if not value:
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="WinRM/IIS query failed (IIS host?)"
            )

        verdict = "FAIL" if value.lower() == "true" else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"directory_browse_enabled": value},
            t0=t0,
            ctx=ctx,
        )


CHECK = _DirectoryBrowseCheck()
register_check(CHECK)
