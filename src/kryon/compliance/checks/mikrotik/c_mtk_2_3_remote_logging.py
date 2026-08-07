"""MTK-2.3 — Remote logging (syslog) action configured.

RouterOS keeps logs in a small memory buffer by default — an attacker who
compromises the router can erase them. A logging action with target=remote
ships events to a syslog/SIEM host. Read via `/system logging action print`.

FAIL if no remote logging action exists. ERROR if the command can't be run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

_DATA_ROW = re.compile(r"^\s*\d+\s", re.MULTILINE)


class _RemoteLoggingCheck:
    control_id = "MTK-2.3"
    control_title = "Remote logging (syslog) action configured"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Ship logs to your SIEM:\n"
        "  /system logging action add name=remote target=remote remote=<siem-ip>\n"
        "  /system logging add topics=info,error,warning action=remote"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "/system logging action print where target=remote"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if rc != 0 and not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="RouterOS CLI call failed")

        remote_actions = len(_DATA_ROW.findall(out))
        verdict = "PASS" if remote_actions > 0 else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"remote_logging_actions": remote_actions},
            t0=t0,
            ctx=ctx,
        )


CHECK = _RemoteLoggingCheck()
register_check(CHECK)
