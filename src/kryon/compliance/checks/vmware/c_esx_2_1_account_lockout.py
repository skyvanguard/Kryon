"""ESX-2.1 — Account lockout policy enforced.

CIS ESXi Benchmark: `/Security/AccountLockFailures` must be > 0 (typically
3–5) so repeated failed logins lock the account and throttle brute force.
0 disables lockout entirely.

FAIL if AccountLockFailures is 0 / unset (or absurdly high > 100).
ERROR if the value can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _int_value(out: str) -> int | None:
    m = re.search(r"Int Value:\s*(-?\d+)", out)
    return int(m.group(1)) if m else None


class _AccountLockoutCheck:
    control_id = "ESX-2.1"
    control_title = "Account lockout policy enforced"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Enable account lockout:\n"
        "  esxcli system settings advanced set -o /Security/AccountLockFailures -i 3\n"
        "  esxcli system settings advanced set -o /Security/AccountUnlockTime -i 900"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system settings advanced list -o /Security/AccountLockFailures"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read advanced setting"}, t0, ctx)

        value = _int_value(out)
        verdict = "PASS" if (value is not None and 0 < value <= 100) else "FAIL"
        return self._result(verdict, cmd, out, err, {"account_lock_failures": value}, t0, ctx)

    def _result(self, verdict, cmd, out, err, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:2048],
            evidence_stderr=err[:512],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _AccountLockoutCheck()
register_check(CHECK)
