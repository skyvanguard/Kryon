"""PG-1.2 — Connection logging enabled.

CIS PostgreSQL Benchmark: `log_connections = on` records every established
session (user, source, time) — the audit trail needed to investigate misuse.
Read via `SHOW log_connections`.

FAIL if log_connections is off. ERROR if psql can't be run.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.postgres._common import make_error, make_result, psql_cmd
from kryon.compliance.runner import register_check, run_cmd


class _LogConnectionsCheck:
    control_id = "PG-1.2"
    control_title = "Connection logging enabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = "Enable in postgresql.conf and reload:\n  log_connections = on"

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = psql_cmd("SHOW log_connections")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="psql call failed (PostgreSQL host?)"
            )

        value = out.strip().lower()
        verdict = "PASS" if value == "on" else "FAIL"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"log_connections": value}, t0=t0, ctx=ctx
        )


CHECK = _LogConnectionsCheck()
register_check(CHECK)
