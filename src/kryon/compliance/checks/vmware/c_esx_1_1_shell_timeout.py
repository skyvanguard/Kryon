"""ESX-1.1 — ESXi Shell / SSH interactive timeout is set.

CIS ESXi Benchmark: `/UserVars/ESXiShellInteractiveTimeOut` must be > 0 so
idle interactive shell / SSH sessions auto-log-out. 0 = never times out — a
walk-away / hijacked-session risk. Read via `esxcli system settings advanced`.

FAIL if the timeout is 0 / unset. ERROR if the value can't be read (not an
ESXi host, or SSH not enabled).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _int_value(out: str) -> int | None:
    m = re.search(r"Int Value:\s*(-?\d+)", out)
    return int(m.group(1)) if m else None


class _ShellTimeoutCheck:
    control_id = "ESX-1.1"
    control_title = "ESXi Shell/SSH interactive timeout enabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        "Set an interactive-session timeout:\n"
        "  esxcli system settings advanced set -o /UserVars/ESXiShellInteractiveTimeOut -i 900\n"
        "(900s = 15 min). Also set /UserVars/ESXiShellTimeOut to auto-stop the\n"
        "shell/SSH service itself."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system settings advanced list -o /UserVars/ESXiShellInteractiveTimeOut"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read advanced setting"}, t0, ctx)

        value = _int_value(out)
        verdict = "PASS" if (value is not None and value > 0) else "FAIL"
        return self._result(verdict, cmd, out, err, {"interactive_timeout": value}, t0, ctx)

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


CHECK = _ShellTimeoutCheck()
register_check(CHECK)
