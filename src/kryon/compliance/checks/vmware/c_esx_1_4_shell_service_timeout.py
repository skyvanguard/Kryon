"""ESX-1.4 — ESXi Shell service auto-stop timeout is set.

CIS ESXi Benchmark: `/UserVars/ESXiShellTimeOut` must be > 0 so the ESXi
Shell / SSH *service* auto-stops after the configured idle period once
enabled — you can't forget it running. (Distinct from ESX-1.1, which
times out an interactive session; this stops the service itself.)

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


class _ShellServiceTimeoutCheck:
    control_id = "ESX-1.4"
    control_title = "ESXi Shell / SSH service auto-stop timeout enabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        "Auto-stop the shell/SSH service after idle:\n"
        "  esxcli system settings advanced set -o /UserVars/ESXiShellTimeOut -i 3600\n"
        "(3600s = 1h). Keep SSH off by default; enable only for the engagement."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system settings advanced list -o /UserVars/ESXiShellTimeOut"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read advanced setting"}, t0, ctx)

        value = _int_value(out)
        verdict = "PASS" if (value is not None and value > 0) else "FAIL"
        return self._result(verdict, cmd, out, err, {"shell_service_timeout": value}, t0, ctx)

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


CHECK = _ShellServiceTimeoutCheck()
register_check(CHECK)
