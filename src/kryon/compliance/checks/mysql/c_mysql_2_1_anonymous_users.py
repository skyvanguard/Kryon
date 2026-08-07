"""MYSQL-2.1 — No anonymous user accounts.

CIS MySQL Benchmark: an account with an empty user name lets anyone connect
without credentials. It's a default on some installs and must be removed.
Read via a COUNT over mysql.user.

FAIL if any anonymous account exists. ERROR if mysql can't be reached.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.mysql._common import make_error, make_result, mysql_cmd, scalar
from kryon.compliance.runner import register_check, run_cmd


class _AnonymousUsersCheck:
    control_id = "MYSQL-2.1"
    control_title = "No anonymous user accounts"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Remove anonymous accounts:\n"
        "  DELETE FROM mysql.user WHERE user='';\n  FLUSH PRIVILEGES;\n"
        "Or run `mysql_secure_installation`."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = mysql_cmd("SELECT COUNT(*) FROM mysql.user WHERE user=''")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        value = scalar(out)
        if not value.isdigit():
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="mysql call failed (MySQL/MariaDB host?)"
            )

        count = int(value)
        verdict = "FAIL" if count > 0 else "PASS"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"anonymous_accounts": count}, t0=t0, ctx=ctx
        )


CHECK = _AnonymousUsersCheck()
register_check(CHECK)
