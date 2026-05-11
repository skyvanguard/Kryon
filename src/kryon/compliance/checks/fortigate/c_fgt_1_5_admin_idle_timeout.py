"""FGT-1.5 — Admin idle timeout <= 5 minutes.

Long idle sessions left on shared workstations are an obvious risk.
FortiOS default `admintimeout` is 5 minutes; many sites bump to 60 or 480
"for convenience". PCI-DSS 8.1.8 caps at 15 minutes.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

# PCI-DSS 8.1.8 ceiling. We also surface a stricter "preferred" of 5min.
_MAX_TIMEOUT_MINUTES = 15
_PREFERRED_TIMEOUT_MINUTES = 5


class _AdminIdleTimeoutCheck:
    control_id = "FGT-1.5"
    control_title = f"Admin idle timeout <= {_MAX_TIMEOUT_MINUTES} minutes"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        f"config system global\n"
        f"  set admintimeout {_PREFERRED_TIMEOUT_MINUTES}\n"
        f"end\n"
        f"Default is 5 min on a fresh FortiGate. Anything > {_MAX_TIMEOUT_MINUTES} min "
        f"is a PCI-DSS 8.1.8 finding."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show system global | grep admintimeout"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        # `grep` returns rc=1 if no match — that means default (5 min) is in
        # effect. Treat as PASS.
        if rc not in (0, 1):
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not read system global"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        m = re.search(r"set\s+admintimeout\s+(\d+)", out)
        timeout_min = int(m.group(1)) if m else _PREFERRED_TIMEOUT_MINUTES

        issues: list[str] = []
        if timeout_min > _MAX_TIMEOUT_MINUTES:
            issues.append(f"admintimeout={timeout_min} > {_MAX_TIMEOUT_MINUTES} min (PCI-DSS 8.1.8 ceiling)")

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:512],
            evidence_stderr=err[:512],
            evidence_parsed={
                "admintimeout_minutes": timeout_min,
                "explicit": bool(m),
                "ceiling_minutes": _MAX_TIMEOUT_MINUTES,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _AdminIdleTimeoutCheck()
register_check(CHECK)
