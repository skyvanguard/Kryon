"""ESX-1.3 — DCUI idle timeout is set.

CIS ESXi Benchmark: `/UserVars/DcuiTimeOut` must be > 0 so an idle Direct
Console User Interface (physical/iLO/iDRAC console) session auto-logs-out.
0 = never — a walk-away risk on the host console. Read via `esxcli system
settings advanced`.

FAIL if the timeout is 0 / unset. ERROR if the value can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _int_value(out: str) -> int | None:
    m = re.search(r"Int Value:\s*(-?\d+)", out)
    return int(m.group(1)) if m else None


class _DcuiTimeoutCheck:
    control_id = "ESX-1.3"
    control_title = "DCUI idle timeout enabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        "Set a DCUI idle timeout:\n"
        "  esxcli system settings advanced set -o /UserVars/DcuiTimeOut -i 600\n"
        "(600s = 10 min)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system settings advanced list -o /UserVars/DcuiTimeOut"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read advanced setting"}, t0, ctx)

        value = _int_value(out)
        verdict = "PASS" if (value is not None and value > 0) else "FAIL"
        return self._result(verdict, cmd, out, err, {"dcui_timeout": value}, t0, ctx)

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


CHECK = _DcuiTimeoutCheck()
register_check(CHECK)
