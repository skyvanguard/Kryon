"""ESX-4.2 — SNMP disabled or hardened (no v1/v2c community).

CIS ESXi Benchmark: SNMP should be disabled, or if required, use v3 only —
never v1/v2c with a plaintext community string. Read via `esxcli system
snmp get`.

FAIL if SNMP is enabled AND a community string is set (v1/v2c). PASS if
disabled, or enabled with no community (v3). ERROR if the command fails.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _SnmpCheck:
    control_id = "ESX-4.2"
    control_title = "SNMP disabled or v3-only (no v1/v2c community)"
    section = "4"
    severity = "MEDIUM"
    remediation_static = (
        "Disable SNMP if unused:\n"
        "  esxcli system snmp set --enable false\n"
        "If required, use v3 with auth+priv and clear any community strings:\n"
        "  esxcli system snmp set --communities '' ; configure v3 users/engine-id."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli system snmp get"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read SNMP config"}, t0, ctx)

        low = out.lower()
        enabled = bool(re.search(r"enable:\s*(true|1|yes)", low))
        m = re.search(r"communities:\s*(.*)", out, re.IGNORECASE)
        community = (m.group(1).strip() if m else "").strip()
        has_community = bool(community) and community.lower() not in ("", "none", "<none>")

        verdict = "FAIL" if (enabled and has_community) else "PASS"
        return self._result(verdict, cmd, out, err, {"enabled": enabled, "has_v1v2c_community": has_community}, t0, ctx)

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


CHECK = _SnmpCheck()
register_check(CHECK)
