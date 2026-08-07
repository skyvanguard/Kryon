"""MYSQL-1.2 — local_infile disabled.

CIS MySQL Benchmark: `local_infile = ON` allows `LOAD DATA LOCAL INFILE`,
which a compromised or malicious client (or SQL injection) can use to read
files from the client host — a data-exfiltration / RCE-assist vector. It
should be OFF. Read via `SELECT @@global.local_infile`.

FAIL if local_infile is ON (1). ERROR if mysql can't be reached.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.mysql._common import make_error, make_result, mysql_cmd, scalar
from kryon.compliance.runner import register_check, run_cmd


class _LocalInfileCheck:
    control_id = "MYSQL-1.2"
    control_title = "local_infile disabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = "Disable in my.cnf and restart:\n  [mysqld]\n  local_infile = 0"

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = mysql_cmd("SELECT @@global.local_infile")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        value = scalar(out)
        if not value:
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="mysql call failed (MySQL/MariaDB host?)"
            )

        verdict = "FAIL" if value in ("1", "ON") else "PASS"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"local_infile": value}, t0=t0, ctx=ctx
        )


CHECK = _LocalInfileCheck()
register_check(CHECK)
