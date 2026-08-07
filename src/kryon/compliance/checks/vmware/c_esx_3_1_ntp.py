"""ESX-3.1 — NTP configured and enabled.

CIS ESXi Benchmark: reliable time is required for log correlation, TLS/cert
validation and vCenter operations. Verifies NTP is enabled with at least one
server via `esxcli system ntp get`.

FAIL if NTP is disabled or no server is configured. ERROR if the command
can't be run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _NtpCheck:
    control_id = "ESX-3.1"
    control_title = "NTP configured and enabled"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Configure NTP and enable it:\n"
        "  esxcli system ntp set --enabled=1 --server=<ntp-host>\n"
        "  # firewall: esxcli network firewall ruleset set -r ntpClient -e true\n"
        "All hosts in a cluster must use the same source."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system ntp get"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read NTP config"}, t0, ctx)

        low = out.lower()
        enabled = bool(re.search(r"enabled:\s*(true|1|yes)", low))
        # "Server: x" (older) or "Servers: [x]" (newer); a bare empty list fails.
        m = re.search(r"servers?:\s*(.+)", low)
        server_field = (m.group(1).strip() if m else "").strip("[]").strip()
        has_server = bool(server_field) and server_field not in ("", "none", "[]")

        verdict = "PASS" if (enabled and has_server) else "FAIL"
        return self._result(verdict, cmd, out, err, {"enabled": enabled, "server": server_field or "(none)"}, t0, ctx)

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


CHECK = _NtpCheck()
register_check(CHECK)
