"""ESX-2.3 — Login banner (issue message) configured.

CIS ESXi Benchmark: a pre-login banner (`/Config/Etc/issue`) presents legal /
authorized-use text at the DCUI and SSH prompt. Many regulatory regimes
require it. Read via `esxcli system settings advanced`.

FAIL if the banner is empty / unset. ERROR if it can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _str_value(out: str) -> str | None:
    m = re.search(r"String Value:\s*(.*)", out)
    return m.group(1).strip() if m else None


class _LoginBannerCheck:
    control_id = "ESX-2.3"
    control_title = "Login banner (issue message) configured"
    section = "2"
    severity = "LOW"
    remediation_static = (
        "Set a pre-login banner:\n"
        "  esxcli system settings advanced set -o /Config/Etc/issue "
        "-s 'Authorized use only. Activity is monitored.'"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system settings advanced list -o /Config/Etc/issue"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read advanced setting"}, t0, ctx)

        banner = _str_value(out) or ""
        verdict = "PASS" if banner.strip() else "FAIL"
        return self._result(verdict, cmd, out, err, {"banner_set": bool(banner.strip())}, t0, ctx)

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


CHECK = _LoginBannerCheck()
register_check(CHECK)
