"""ESX-5.1 — Password complexity policy enforced.

CIS ESXi Benchmark: `/Security/PasswordQualityControl` sets the pam_passwdqc
policy. It must enforce a real minimum length — the `min=N0,N1,N2,N3,N4`
field (last value = min length for passwords using all char classes) should
be at least 7 (CIS floor).

FAIL if PasswordQualityControl is empty/unset, or no `min=` field enforces
>= 7. ERROR if the value can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_MIN_FLOOR = 7


def _str_value(out: str) -> str | None:
    m = re.search(r"String Value:\s*(.*)", out)
    return m.group(1).strip() if m else None


def _max_min_length(policy: str) -> int | None:
    """Extract the highest numeric value from the `min=a,b,c,d,e` field."""
    m = re.search(r"min=([\w,]+)", policy)
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(",") if x.isdigit()]
    return max(nums) if nums else None


class _PasswordComplexityCheck:
    control_id = "ESX-5.1"
    control_title = "Password complexity policy enforced"
    section = "5"
    severity = "MEDIUM"
    remediation_static = (
        "Enforce password complexity:\n"
        "  esxcli system settings advanced set -o /Security/PasswordQualityControl "
        "-s 'retry=3 min=disabled,disabled,disabled,7,7'\n"
        "Raise the min lengths for a stronger policy."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system settings advanced list -o /Security/PasswordQualityControl"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read advanced setting"}, t0, ctx)

        policy = _str_value(out) or ""
        max_min = _max_min_length(policy)
        verdict = "PASS" if (max_min is not None and max_min >= _MIN_FLOOR) else "FAIL"
        return self._result(verdict, cmd, out, err, {"policy": policy or "(unset)", "max_min_length": max_min}, t0, ctx)

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


CHECK = _PasswordComplexityCheck()
register_check(CHECK)
