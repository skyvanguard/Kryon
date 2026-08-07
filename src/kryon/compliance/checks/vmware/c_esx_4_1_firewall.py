"""ESX-4.1 — ESXi firewall enabled with default-deny.

CIS ESXi Benchmark: the host firewall must be enabled and its default
action DROP, so only explicitly-allowed services are reachable. Verified via
`esxcli network firewall get`.

FAIL if the firewall is disabled or the default action is PASS (allow).
ERROR if the command can't be run.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _FirewallCheck:
    control_id = "ESX-4.1"
    control_title = "ESXi firewall enabled with default-deny"
    section = "4"
    severity = "HIGH"
    remediation_static = (
        "Enable the ESXi firewall with a default-deny policy:\n"
        "  esxcli network firewall set --enabled true\n"
        "  esxcli network firewall set --default-action false   # false = DROP\n"
        "Then allow only the required rulesets."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "esxcli network firewall get"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read firewall config"}, t0, ctx)

        low = out.lower()
        enabled = bool(re.search(r"enabled:\s*(true|1|yes)", low))
        m = re.search(r"default action:\s*(\w+)", low)
        default_action = m.group(1) if m else ""
        default_deny = default_action == "drop"

        issues: list[str] = []
        if not enabled:
            issues.append("firewall disabled")
        if not default_deny:
            issues.append(f"default action is {default_action or 'unknown'} (not DROP)")

        verdict = "PASS" if not issues else "FAIL"
        return self._result(
            verdict, cmd, out, err, {"enabled": enabled, "default_action": default_action, "issues": issues}, t0, ctx
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


CHECK = _FirewallCheck()
register_check(CHECK)
