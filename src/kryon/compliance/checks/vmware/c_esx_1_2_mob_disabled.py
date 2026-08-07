"""ESX-1.2 — Managed Object Browser (MOB) disabled.

CIS ESXi Benchmark: `/Config/HostAgent/plugins/solo/enableMob` must be 0.
The MOB is a debug web interface that exposes the host's full object model
and has been used for credential/config disclosure — it should be off in
production.

FAIL if enableMob is 1. ERROR if the value can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _int_value(out: str) -> int | None:
    m = re.search(r"Int Value:\s*(-?\d+)", out)
    return int(m.group(1)) if m else None


class _MobCheck:
    control_id = "ESX-1.2"
    control_title = "Managed Object Browser (MOB) disabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        "Disable the MOB:\n  esxcli system settings advanced set -o /Config/HostAgent/plugins/solo/enableMob -i 0"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system settings advanced list -o /Config/HostAgent/plugins/solo/enableMob"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read advanced setting"}, t0, ctx)

        value = _int_value(out)
        verdict = "PASS" if value == 0 else "FAIL"
        return self._result(verdict, cmd, out, err, {"enable_mob": value}, t0, ctx)

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


CHECK = _MobCheck()
register_check(CHECK)
