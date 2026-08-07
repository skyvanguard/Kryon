"""FGT-1.8 — Admin password policy enforced.

`config system password-policy` sets complexity/length/expiry for admin
credentials. CIS Fortinet Benchmark requires it enabled with a minimum
length. `get system password-policy` shows the effective values.

FAIL if the policy status is not enable, or minimum-length < 8. ERROR if
the value can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_MIN_LENGTH = 8


def _get_value(out: str, key: str) -> str | None:
    m = re.search(rf"^{re.escape(key)}\s*:\s*(.+)$", out, re.M)
    return m.group(1).strip() if m else None


class _PasswordPolicyCheck:
    control_id = "FGT-1.8"
    control_title = "Admin password policy enforced"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Enable and tighten the admin password policy:\n"
        "  config system password-policy\n"
        "    set status enable\n"
        "    set minimum-length 12\n"
        "    set min-lower-case-letter 1  set min-upper-case-letter 1\n"
        "    set min-number 1  set min-non-alphanumeric 1\n"
        "    set expire-status enable  set expire-day 90\n"
        "  end"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "get system password-policy"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out:
            return self._result("ERROR", cmd, out, err, {"reason": "could not read password-policy"}, t0, ctx)

        status = _get_value(out, "status")
        min_len_raw = _get_value(out, "minimum-length")
        try:
            min_len = int(min_len_raw) if min_len_raw is not None else None
        except ValueError:
            min_len = None

        issues: list[str] = []
        if status != "enable":
            issues.append(f"password-policy status={status or '(unset)'}")
        if min_len is None or min_len < _MIN_LENGTH:
            issues.append(f"minimum-length={min_len_raw or '(unset)'} (< {_MIN_LENGTH})")

        verdict = "PASS" if not issues else "FAIL"
        return self._result(
            verdict,
            cmd,
            out,
            err,
            {"status": status, "minimum_length": min_len_raw, "issues": issues},
            t0,
            ctx,
        )

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


CHECK = _PasswordPolicyCheck()
register_check(CHECK)
