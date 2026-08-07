"""MYSQL-2.2 — root not reachable from any host.

CIS MySQL Benchmark: a `root`@`%` account lets the superuser authenticate
from any network address, turning one leaked/guessed password into full
compromise. root should be limited to localhost. Read via a COUNT over
mysql.user.

FAIL if a root account with host='%' exists. ERROR if mysql can't be reached.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.mysql._common import make_error, make_result, mysql_cmd, scalar
from kryon.compliance.runner import register_check, run_cmd


class _RootAnyHostCheck:
    control_id = "MYSQL-2.2"
    control_title = "root not reachable from any host"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Restrict root to localhost:\n"
        "  RENAME USER 'root'@'%' TO 'root'@'localhost';   -- or DROP it\n"
        "  FLUSH PRIVILEGES;\n"
        "Use a dedicated, least-privilege admin account for remote work."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = mysql_cmd("SELECT COUNT(*) FROM mysql.user WHERE user='root' AND host='%'")
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
            parsed={"root_any_host_accounts": count},
            t0=t0,
            ctx=ctx,
        )


CHECK = _RootAnyHostCheck()
register_check(CHECK)
