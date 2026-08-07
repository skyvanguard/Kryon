"""ESX-3.2 — Remote syslog configured.

CIS ESXi Benchmark: ESXi has limited local log storage, so logs must be
forwarded to a remote host / vRealize Log Insight / SIEM. Verifies a remote
loghost via `esxcli system syslog config get`.

FAIL if no remote host is set (<none>). ERROR if the command can't be run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _RemoteSyslogCheck:
    control_id = "ESX-3.2"
    control_title = "Remote syslog (loghost) configured"
    section = "3"
    severity = "HIGH"
    remediation_static = (
        "Point ESXi logs at your SIEM:\n"
        "  esxcli system syslog config set --loghost='tcp://siem.corp:514'\n"
        "  esxcli system syslog reload\n"
        "  esxcli network firewall ruleset set -r syslog -e true"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system syslog config get"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read syslog config"}, t0, ctx)

        m = re.search(r"Remote Host:\s*(.+)", out)
        remote = (m.group(1).strip() if m else "").strip()
        configured = bool(remote) and remote.lower() not in ("<none>", "none", "")

        verdict = "PASS" if configured else "FAIL"
        return self._result(verdict, cmd, out, err, {"remote_host": remote or "<none>"}, t0, ctx)

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


CHECK = _RemoteSyslogCheck()
register_check(CHECK)
