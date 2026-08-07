"""ESX-3.3 — NTP client firewall ruleset enabled.

Complements ESX-3.1: NTP can be *configured* yet still fail to sync if the
`ntpClient` firewall ruleset is disabled (with ESX-4.1's default-deny, the
outbound NTP is blocked). Verified via `esxcli network firewall ruleset
list -r ntpClient`.

FAIL if the ntpClient ruleset is disabled. ERROR if it can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _NtpFirewallCheck:
    control_id = "ESX-3.3"
    control_title = "NTP client firewall ruleset enabled"
    section = "3"
    severity = "LOW"
    remediation_static = (
        "Allow outbound NTP through the ESXi firewall:\n  esxcli network firewall ruleset set -r ntpClient -e true"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli network firewall ruleset list -r ntpClient"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read firewall ruleset"}, t0, ctx)

        # Row form: "ntpClient  true" (or false). Grab the token after the name.
        m = re.search(r"ntpClient\s+(\w+)", out, re.IGNORECASE)
        enabled = bool(m) and m.group(1).lower() in ("true", "1", "yes")
        verdict = "PASS" if enabled else "FAIL"
        return self._result(verdict, cmd, out, err, {"ntpclient_ruleset_enabled": enabled}, t0, ctx)

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


CHECK = _NtpFirewallCheck()
register_check(CHECK)
