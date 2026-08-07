"""PG-1.1 — SSL/TLS enabled.

CIS PostgreSQL Benchmark: `ssl = on` encrypts client connections, protecting
credentials and query data in transit. Read via `SHOW ssl`.

FAIL if ssl is off. ERROR if psql can't be run (not a PostgreSQL host / no
local postgres access).
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.postgres._common import make_error, make_result, psql_cmd
from kryon.compliance.runner import register_check, run_cmd


class _SslCheck:
    control_id = "PG-1.1"
    control_title = "SSL/TLS enabled"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Enable TLS in postgresql.conf:\n"
        "  ssl = on\n"
        "Provide server.crt / server.key (0600, owned by postgres) and reload."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = psql_cmd("SHOW ssl")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="psql call failed (PostgreSQL host?)"
            )

        value = out.strip().lower()
        verdict = "PASS" if value == "on" else "FAIL"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"ssl": value}, t0=t0, ctx=ctx
        )


CHECK = _SslCheck()
register_check(CHECK)
