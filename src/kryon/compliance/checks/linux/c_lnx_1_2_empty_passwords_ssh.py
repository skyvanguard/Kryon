"""LNX-1.2 — SSH does not permit empty passwords.

CIS Linux Benchmark: `PermitEmptyPasswords yes` lets an account whose password
field is blank log in over SSH with no credential at all. It must be no (the
default). Read from the effective sshd config (`sshd -T`).

FAIL if PermitEmptyPasswords is yes. PASS if no. ERROR if the sshd config
can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _EmptyPasswordsSshCheck:
    control_id = "LNX-1.2"
    control_title = "SSH does not permit empty passwords"
    section = "1"
    severity = "HIGH"
    remediation_static = "In /etc/ssh/sshd_config:\n  PermitEmptyPasswords no\nRestart sshd."

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "sshd -T 2>/dev/null | grep -iE '^permitemptypasswords' || true"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="could not read sshd config")

        m = re.search(r"permitemptypasswords\s+(\S+)", out, re.IGNORECASE)
        value = m.group(1).lower() if m else None
        verdict = "FAIL" if value == "yes" else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"permit_empty_passwords": value},
            t0=t0,
            ctx=ctx,
        )


CHECK = _EmptyPasswordsSshCheck()
register_check(CHECK)
