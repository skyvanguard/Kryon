"""MYSQL-1.1 — TLS required for client connections.

CIS MySQL Benchmark: `require_secure_transport = ON` forces every client to
use TLS, so credentials and query data can't cross the network in cleartext.
Read via `SELECT @@global.require_secure_transport`.

FAIL if it is OFF (0). N/A if the variable is absent (older MariaDB) or mysql
can't be reached — we don't guess a verdict we can't see.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.mysql._common import make_result, mysql_cmd, scalar
from kryon.compliance.runner import register_check, run_cmd


class _RequireTlsCheck:
    control_id = "MYSQL-1.1"
    control_title = "TLS required for client connections"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Force TLS in my.cnf and restart:\n"
        "  [mysqld]\n  require_secure_transport = ON\n"
        "Provide ssl-cert / ssl-key / ssl-ca; test clients still connect over TLS."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = mysql_cmd("SELECT @@global.require_secure_transport")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        value = scalar(out)
        if not value:
            return make_result(
                check=self,
                verdict="N/A",
                cmd=cmd,
                out=out,
                err=err,
                parsed={"reason": "require_secure_transport unavailable (older version / mysql inaccessible)"},
                t0=t0,
                ctx=ctx,
            )
        verdict = "PASS" if value in ("1", "ON") else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"require_secure_transport": value},
            t0=t0,
            ctx=ctx,
        )


CHECK = _RequireTlsCheck()
register_check(CHECK)
