"""MYSQL-2.3 — Default `test` database removed.

CIS MySQL Benchmark: the default `test` schema is world-accessible (any user,
including anonymous, can use it), providing a foothold for reconnaissance and
privilege probing. It should be dropped. Read via information_schema.

FAIL if a `test` database exists. ERROR if mysql can't be reached.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.mysql._common import make_error, make_result, mysql_cmd, scalar
from kryon.compliance.runner import register_check, run_cmd


class _TestDatabaseCheck:
    control_id = "MYSQL-2.3"
    control_title = "Default test database removed"
    section = "2"
    severity = "MEDIUM"
    remediation_static = "Drop it:\n  DROP DATABASE test;\nOr run `mysql_secure_installation`."

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = mysql_cmd("SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='test'")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        value = scalar(out)
        if not value.isdigit():
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="mysql call failed (MySQL/MariaDB host?)"
            )

        count = int(value)
        verdict = "FAIL" if count > 0 else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"test_database_present": count > 0},
            t0=t0,
            ctx=ctx,
        )


CHECK = _TestDatabaseCheck()
register_check(CHECK)
