"""ESX-6.2 — VIB acceptance level is not CommunitySupported.

CIS ESXi Benchmark: the host image/software acceptance level controls which
VIBs (drivers/extensions) may be installed. `CommunitySupported` allows
unsigned, unvetted code — a supply-chain risk. It must be at least
`PartnerSupported` (ideally `VMwareCertified` / `VMwareAccepted`).

FAIL if the acceptance level is CommunitySupported. ERROR if unreadable.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_ACCEPTABLE = {"vmwarecertified", "vmwareaccepted", "partnersupported"}


class _VibAcceptanceCheck:
    control_id = "ESX-6.2"
    control_title = "VIB acceptance level not CommunitySupported"
    section = "6"
    severity = "MEDIUM"
    remediation_static = (
        "Raise the host acceptance level so unsigned VIBs are rejected:\n"
        "  esxcli software acceptance set --level PartnerSupported\n"
        "(or VMwareAccepted / VMwareCertified). Re-verify installed VIBs comply."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli software acceptance get"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read acceptance level"}, t0, ctx)

        level = out.strip().splitlines()[0].strip() if out.strip() else ""
        verdict = "PASS" if level.lower() in _ACCEPTABLE else "FAIL"
        return self._result(verdict, cmd, out, err, {"acceptance_level": level or "(unknown)"}, t0, ctx)

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


CHECK = _VibAcceptanceCheck()
register_check(CHECK)
