"""ESX-5.2 — Password history / reuse prevention enforced.

CIS ESXi Benchmark: `/Security/PasswordHistory` must be >= 5 so the last N
passwords can't be reused, defeating rotate-back. 0 = reuse allowed.

FAIL if PasswordHistory is < 5 / unset. ERROR if the value can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_MIN_HISTORY = 5


def _int_value(out: str) -> int | None:
    m = re.search(r"Int Value:\s*(-?\d+)", out)
    return int(m.group(1)) if m else None


class _PasswordHistoryCheck:
    control_id = "ESX-5.2"
    control_title = "Password history (reuse prevention) enforced"
    section = "5"
    severity = "LOW"
    remediation_static = (
        "Prevent password reuse:\n  esxcli system settings advanced set -o /Security/PasswordHistory -i 5"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system settings advanced list -o /Security/PasswordHistory"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read advanced setting"}, t0, ctx)

        value = _int_value(out)
        verdict = "PASS" if (value is not None and value >= _MIN_HISTORY) else "FAIL"
        return self._result(verdict, cmd, out, err, {"password_history": value}, t0, ctx)

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


CHECK = _PasswordHistoryCheck()
register_check(CHECK)
