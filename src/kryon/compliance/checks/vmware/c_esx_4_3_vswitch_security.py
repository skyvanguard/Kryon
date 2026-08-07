"""ESX-4.3 — Standard vSwitch security policies hardened.

CIS ESXi Benchmark: every standard vSwitch must Reject
  - Promiscuous Mode      (else a guest can sniff other VMs' traffic)
  - MAC Address Changes   (else a guest can impersonate another MAC)
  - Forged Transmits      (else a guest can spoof source MACs)

Enumerates standard vSwitches via `esxcli network vswitch standard list`,
then reads each one's security policy. FAIL if any vSwitch allows any of
the three. ERROR if the switch list can't be read. N/A if there are no
standard vSwitches (fully-DVS environment — checked at vCenter).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def _allows(policy_out: str, key: str) -> bool:
    """True if the named 'Allow ...' policy is set to true (insecure)."""
    m = re.search(rf"{re.escape(key)}:\s*(\w+)", policy_out, re.IGNORECASE)
    return bool(m) and m.group(1).lower() in ("true", "1", "yes")


class _VSwitchSecurityCheck:
    control_id = "ESX-4.3"
    control_title = "Standard vSwitch security policies (promiscuous/MAC/forged) rejected"
    section = "4"
    severity = "HIGH"
    remediation_static = (
        "Reject the three L2 policies on every standard vSwitch (and port group):\n"
        "  esxcli network vswitch standard policy security set -v <vSwitch> \\\n"
        "    --allow-promiscuous false --allow-mac-change false --allow-forged-transmits false"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        list_cmd = "esxcli network vswitch standard list"
        out, err, rc = run_cmd(ctx, list_cmd, shell=True, timeout_s=10)
        if rc != 0 and not out.strip():
            return self._result("ERROR", list_cmd, out, err, {"reason": "could not list vSwitches"}, t0, ctx)

        names = sorted({n for n in re.findall(r"Name:\s*(\S+)", out) if _SAFE_NAME.match(n)})
        if not names:
            return self._result("N/A", list_cmd, out, err, {"reason": "no standard vSwitches"}, t0, ctx)

        per_switch: dict[str, dict] = {}
        any_insecure = False
        for name in names:
            pol, _, _ = run_cmd(
                ctx, f"esxcli network vswitch standard policy security get -v {name}", shell=True, timeout_s=8
            )
            insecure = {
                "promiscuous": _allows(pol, "Allow Promiscuous"),
                "mac_change": _allows(pol, "Allow MAC Address Change"),
                "forged": _allows(pol, "Allow Forged Transmits"),
            }
            per_switch[name] = insecure
            if any(insecure.values()):
                any_insecure = True

        verdict = "FAIL" if any_insecure else "PASS"
        return self._result(verdict, list_cmd, out, err, {"vswitches": per_switch}, t0, ctx)

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


CHECK = _VSwitchSecurityCheck()
register_check(CHECK)
