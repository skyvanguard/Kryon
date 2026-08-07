"""ESX-2.2 — Account unlock time enforced.

CIS ESXi Benchmark: `/Security/AccountUnlockTime` must be > 0 so a locked
account (after ESX-2.1's failure threshold) stays locked for a defined
period, actually throttling brute force. 0 = unlocks immediately, which
defeats the lockout.

FAIL if AccountUnlockTime is 0 / unset. ERROR if the value can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _int_value(out: str) -> int | None:
    m = re.search(r"Int Value:\s*(-?\d+)", out)
    return int(m.group(1)) if m else None


class _AccountUnlockTimeCheck:
    control_id = "ESX-2.2"
    control_title = "Account unlock time enforced"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Set a lockout duration (pairs with ESX-2.1):\n"
        "  esxcli system settings advanced set -o /Security/AccountUnlockTime -i 900\n"
        "(900s = 15 min)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system settings advanced list -o /Security/AccountUnlockTime"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read advanced setting"}, t0, ctx)

        value = _int_value(out)
        verdict = "PASS" if (value is not None and value > 0) else "FAIL"
        return self._result(verdict, cmd, out, err, {"account_unlock_time": value}, t0, ctx)

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


CHECK = _AccountUnlockTimeCheck()
register_check(CHECK)
