"""PG-2.2 — No `trust` authentication on network (host) rules.

CIS PostgreSQL Benchmark: a `trust` rule in pg_hba.conf accepts a connection
with NO password. On a network (host / hostssl / hostnossl) rule that is a
full authentication bypass. Read via the pg_hba_file_rules view (effective
rules).

FAIL if any host-type rule uses auth_method = trust. ERROR if psql can't be
run.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.postgres._common import make_error, make_result, psql_cmd
from kryon.compliance.runner import register_check, run_cmd


class _NoNetworkTrustCheck:
    control_id = "PG-2.2"
    control_title = "No trust authentication on network (host) rules"
    section = "2"
    severity = "CRITICAL"
    remediation_static = (
        "Replace `trust` on host rules in pg_hba.conf with scram-sha-256 (or\n"
        "cert for mTLS), then `SELECT pg_reload_conf();`. Reserve trust — if at\n"
        "all — for local/unix-socket rules with tight peer mapping."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        # No SQL string literals -> no nested-quote escaping over SSH+su+psql.
        cmd = psql_cmd("SELECT type, auth_method FROM pg_hba_file_rules")
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)
        if not out.strip():
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="psql call failed (PostgreSQL host?)"
            )

        offenders = 0
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) >= 2 and parts[0].strip().lower().startswith("host") and parts[1].strip().lower() == "trust":
                offenders += 1

        verdict = "FAIL" if offenders else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"network_trust_rules": offenders},
            t0=t0,
            ctx=ctx,
        )


CHECK = _NoNetworkTrustCheck()
register_check(CHECK)
