"""FGT-2.5 — Global strong-crypto enabled.

`config system global` → `strong-crypto` forces the FortiGate to use
strong ciphers/algorithms for its own SSL/SSH (admin GUI, SSL-VPN,
FortiGuard, LDAPS, etc.). CIS Fortinet Benchmark requires it enabled;
default is disable. `get system global` shows the effective value.

FAIL if strong-crypto is not enable. ERROR if the value can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _get_value(out: str, key: str) -> str | None:
    m = re.search(rf"^{re.escape(key)}\s*:\s*(.+)$", out, re.M)
    return m.group(1).strip() if m else None


class _StrongCryptoCheck:
    control_id = "FGT-2.5"
    control_title = "Global strong-crypto enabled"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Force strong ciphers for the device's own SSL/SSH:\n"
        "  config system global\n"
        "    set strong-crypto enable\n"
        "  end\n"
        "Verify management clients / integrations still negotiate after enabling."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "get system global"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out:
            return self._result("ERROR", cmd, out, err, {"reason": "could not read system global"}, t0, ctx)

        value = _get_value(out, "strong-crypto")
        verdict = "PASS" if value == "enable" else "FAIL"
        return self._result(verdict, cmd, out, err, {"strong_crypto": value or "(default disable)"}, t0, ctx)

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


CHECK = _StrongCryptoCheck()
register_check(CHECK)
