"""PVE-5.3 — Automatic security updates enabled.

PVE-5.1 flags pending patches at scan time; 5.3 checks that the node keeps
itself current between scans. `unattended-upgrades` must be installed AND
enabled (APT::Periodic::Unattended-Upgrade "1") so security fixes land
without a manual window.

FAIL if the package is missing or the periodic job is disabled. ERROR if
the config can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _UnattendedUpgradesCheck:
    control_id = "PVE-5.3"
    control_title = "Automatic security updates enabled (unattended-upgrades)"
    section = "5"
    severity = "MEDIUM"
    remediation_static = (
        "Enable automatic security patching:\n"
        "  apt install unattended-upgrades\n"
        "  dpkg-reconfigure -plow unattended-upgrades   # writes 20auto-upgrades\n"
        "Ensure /etc/apt/apt.conf.d/20auto-upgrades has:\n"
        '  APT::Periodic::Update-Package-Lists "1";\n'
        '  APT::Periodic::Unattended-Upgrade "1";'
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "dpkg -l unattended-upgrades 2>/dev/null | grep -c '^ii' ; "
            "cat /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/*periodic* 2>/dev/null"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read upgrade config"}, t0, ctx)

        lines = out.splitlines()
        installed = bool(lines) and lines[0].strip() == "1"
        # APT::Periodic::Unattended-Upgrade "1";  -> periodic job enabled
        enabled = bool(re.search(r'Unattended-Upgrade"?\s+"1"', out))

        issues: list[str] = []
        if not installed:
            issues.append("unattended-upgrades not installed")
        if not enabled:
            issues.append('APT::Periodic::Unattended-Upgrade not set to "1"')

        verdict = "PASS" if not issues else "FAIL"
        return self._result(
            verdict, cmd, out, err, {"installed": installed, "periodic_enabled": enabled, "issues": issues}, t0, ctx
        )

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


CHECK = _UnattendedUpgradesCheck()
register_check(CHECK)
