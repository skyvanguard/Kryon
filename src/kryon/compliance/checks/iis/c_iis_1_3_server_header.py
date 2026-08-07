"""IIS-1.3 — Server header removed (version disclosure).

CIS IIS Benchmark: the `Server: Microsoft-IIS/x.y` response header advertises
the IIS version. requestFiltering `removeServerHeader = True` (IIS 10+) strips
it.

FAIL if removeServerHeader is False. PASS if True. N/A if the property doesn't
exist (IIS < 10 — the setting is unavailable, so we don't guess). ERROR only
if the WinRM channel itself fails.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.iis._common import last_value, make_result, webconfig
from kryon.compliance.runner import register_check, run_cmd


class _ServerHeaderCheck:
    control_id = "IIS-1.3"
    control_title = "Server header removed (version disclosure)"
    section = "1"
    severity = "LOW"
    remediation_static = (
        "Strip the Server header (IIS 10+, PowerShell admin):\n"
        "  Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' "
        "-filter 'system.webServer/security/requestFiltering' -name removeServerHeader -value True"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = webconfig("system.webServer/security/requestFiltering", "removeServerHeader")
        out, err, rc = run_cmd(ctx, cmd, timeout_s=25)
        value = last_value(out)
        if not value:
            # Property is IIS 10+ only; treat absence as not-assessable, not a fail.
            return make_result(
                check=self,
                verdict="N/A",
                cmd=cmd,
                out=out,
                err=err,
                parsed={"reason": "removeServerHeader unavailable (IIS < 10 or query failed)"},
                t0=t0,
                ctx=ctx,
            )

        verdict = "PASS" if value.lower() == "true" else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"remove_server_header": value},
            t0=t0,
            ctx=ctx,
        )


CHECK = _ServerHeaderCheck()
register_check(CHECK)
