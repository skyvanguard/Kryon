"""LNX-1.1 — SSH does not permit password root login.

CIS Linux Benchmark: `PermitRootLogin yes` lets root authenticate over the
network with a password — the single most brute-forced login on the internet.
Read from the effective sshd config (`sshd -T`).

FAIL only if PermitRootLogin is `yes` (password root login) — `no`,
`prohibit-password` and `without-password` are all accepted so key-only root
isn't a false positive. ERROR if the sshd config can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _RootLoginCheck:
    control_id = "LNX-1.1"
    control_title = "SSH does not permit password root login"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "In /etc/ssh/sshd_config:\n  PermitRootLogin no\n(or prohibit-password for key-only root). Restart sshd."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "sshd -T 2>/dev/null | grep -iE '^permitrootlogin' || true"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="could not read sshd config")

        m = re.search(r"permitrootlogin\s+(\S+)", out, re.IGNORECASE)
        value = m.group(1).lower() if m else None
        verdict = "FAIL" if value == "yes" else "PASS"
        return make_result(
            check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed={"permit_root_login": value}, t0=t0, ctx=ctx
        )


CHECK = _RootLoginCheck()
register_check(CHECK)
