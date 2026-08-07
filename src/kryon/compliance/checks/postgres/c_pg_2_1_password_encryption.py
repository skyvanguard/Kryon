"""PG-2.1 — password_encryption uses scram-sha-256.

CIS PostgreSQL Benchmark: `md5` password hashes are weak and replayable;
`scram-sha-256` (default since PG 14) is the secure algorithm. Read via
`SHOW password_encryption`.

FAIL if password_encryption is not scram-sha-256 (e.g. md5). ERROR if psql
can't be run.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.postgres._common import make_error, make_result, psql_cmd
from kryon.compliance.runner import register_check, run_cmd


class _PasswordEncryptionCheck:
    control_id = "PG-2.1"
    control_title = "password_encryption uses scram-sha-256"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Set in postgresql.conf and reload:\n"
        "  password_encryption = scram-sha-256\n"
        "Then have users reset passwords so the new hash is stored."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = psql_cmd("SHOW password_encryption")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="psql call failed (PostgreSQL host?)"
            )

        value = out.strip().lower()
        verdict = "PASS" if value == "scram-sha-256" else "FAIL"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"password_encryption": value},
            t0=t0,
            ctx=ctx,
        )


CHECK = _PasswordEncryptionCheck()
register_check(CHECK)
