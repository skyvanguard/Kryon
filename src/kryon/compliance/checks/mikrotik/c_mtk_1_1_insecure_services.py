"""MTK-1.1 — Cleartext management services disabled.

RouterOS ships telnet, ftp, www (HTTP) and api (non-TLS) as management
services. All send credentials/config in cleartext and should be disabled in
favour of ssh, winbox (TLS) and api-ssl. Read via `/ip service print`.

FAIL if any of telnet / ftp / www / api is enabled. ERROR if the command
can't be run (not a RouterOS device / SSH off).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

_INSECURE = {"telnet", "ftp", "www", "api"}
# Enabled service rows have no 'X' (disabled) flag: "<n>   <name>  <port> ..."
_ROW_RE = re.compile(r"^\s*\d+\s+([a-z][a-z0-9-]*)\s", re.MULTILINE)


class _InsecureServicesCheck:
    control_id = "MTK-1.1"
    control_title = "Cleartext management services (telnet/ftp/www/api) disabled"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Disable the cleartext services:\n"
        "  /ip service disable telnet,ftp,www,api\n"
        "Manage the router over ssh / winbox (TLS) / api-ssl only."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "/ip service print where disabled=no"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if rc != 0 and not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="RouterOS CLI call failed")

        enabled = {m.group(1) for m in _ROW_RE.finditer(out)}
        offenders = sorted(_INSECURE & enabled)
        verdict = "FAIL" if offenders else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"insecure_enabled": offenders},
            t0=t0,
            ctx=ctx,
        )


CHECK = _InsecureServicesCheck()
register_check(CHECK)
