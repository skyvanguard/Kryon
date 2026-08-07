"""PG-1.3 — Disconnection logging enabled.

CIS PostgreSQL Benchmark: `log_disconnections = on` records session end and
duration, completing the connection audit trail (paired with PG-1.2). Read
via `SHOW log_disconnections`.

FAIL if log_disconnections is off. ERROR if psql can't be run.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.postgres._common import make_error, make_result, psql_cmd
from kryon.compliance.runner import register_check, run_cmd


class _LogDisconnectionsCheck:
    control_id = "PG-1.3"
    control_title = "Disconnection logging enabled"
    section = "1"
    severity = "LOW"
    remediation_static = "Enable in postgresql.conf and reload:\n  log_disconnections = on"

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = psql_cmd("SHOW log_disconnections")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="psql call failed (PostgreSQL host?)"
            )

        value = out.strip().lower()
        verdict = "PASS" if value == "on" else "FAIL"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"log_disconnections": value}, t0=t0, ctx=ctx
        )


CHECK = _LogDisconnectionsCheck()
register_check(CHECK)
