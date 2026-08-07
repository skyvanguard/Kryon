"""LNX-2.2 — Only root has UID 0.

CIS Linux Benchmark: any account with UID 0 has full root privileges. There
must be exactly one — `root`. A second UID-0 account is a classic persistence
/ backdoor technique. Read from /etc/passwd (world-readable).

FAIL if any non-root account has UID 0. ERROR if /etc/passwd can't be read.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _Uid0Check:
    control_id = "LNX-2.2"
    control_title = "Only root has UID 0"
    section = "2"
    severity = "CRITICAL"
    remediation_static = (
        "Investigate and remove/renumber the extra UID-0 account:\n"
        "  awk -F: '($3==0){print $1}' /etc/passwd\n"
        "Only `root` should appear."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="/etc/passwd not readable")

        accounts = [ln.strip() for ln in out.splitlines() if ln.strip()]
        extra = sorted(a for a in accounts if a != "root")
        verdict = "FAIL" if extra else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"extra_uid0_accounts": extra},
            t0=t0,
            ctx=ctx,
        )


CHECK = _Uid0Check()
register_check(CHECK)
