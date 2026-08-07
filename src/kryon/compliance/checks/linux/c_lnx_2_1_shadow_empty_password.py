"""LNX-2.1 — No accounts with an empty password field.

CIS Linux Benchmark: an account whose /etc/shadow password field is empty can
be logged into with no password (subject to PAM). These must be locked or
given a password.

FAIL if any account has an empty password field. ERROR if /etc/shadow can't
be read (need root).
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

_NOREAD = "__KRYON_NOREAD__"


class _ShadowEmptyPasswordCheck:
    control_id = "LNX-2.1"
    control_title = "No accounts with an empty password field"
    section = "2"
    severity = "CRITICAL"
    remediation_static = (
        "Lock or set a password on the offending accounts:\n"
        "  passwd -l <user>    # lock\n  passwd <user>       # set a password"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = f"test -r /etc/shadow && awk -F: '($2==\"\"){{print $1}}' /etc/shadow || echo {_NOREAD}"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if _NOREAD in out or (not out.strip() and rc != 0):
            return make_error(
                self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="/etc/shadow not readable (need root)"
            )

        accounts = [ln.strip() for ln in out.splitlines() if ln.strip() and ln.strip() != _NOREAD]
        verdict = "FAIL" if accounts else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"empty_password_accounts": accounts},
            t0=t0,
            ctx=ctx,
        )


CHECK = _ShadowEmptyPasswordCheck()
register_check(CHECK)
