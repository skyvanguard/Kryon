"""FGT-1.9 — Maintainer recovery account disabled.

`config system global` → `admin-maintainer` enables the `maintainer`
account, which lets anyone with physical console access reset the admin
password (using the device serial). CIS Fortinet Benchmark requires it
disabled for high-security deployments. Default is enable, so `get system
global` shows the effective value.

FAIL if admin-maintainer is enable (or effectively enabled by default).
ERROR if the value can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _get_value(out: str, key: str) -> str | None:
    m = re.search(rf"^{re.escape(key)}\s*:\s*(.+)$", out, re.M)
    return m.group(1).strip() if m else None


class _MaintainerCheck:
    control_id = "FGT-1.9"
    control_title = "Maintainer recovery account disabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        "Disable the physical-console password-recovery account:\n"
        "  config system global\n"
        "    set admin-maintainer disable\n"
        "  end\n"
        "Only do this with a documented break-glass alternative — otherwise a lost\n"
        "admin password means an RMA. Pair with strict physical access control."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "get system global"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out:
            return self._result("ERROR", cmd, out, err, {"reason": "could not read system global"}, t0, ctx)

        value = _get_value(out, "admin-maintainer")
        # Effective default is 'enable'; anything other than an explicit 'disable' is a fail.
        verdict = "PASS" if value == "disable" else "FAIL"
        return self._result(verdict, cmd, out, err, {"admin_maintainer": value or "(default enable)"}, t0, ctx)

    def _result(self, verdict, cmd, out, err, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:3072],
            evidence_stderr=err[:512],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _MaintainerCheck()
register_check(CHECK)
