"""F84.4 — IEC 60870-5-104 check 2.1: Perimeter exposure check.

Even when STARTDT is gated by allowlist, the RTU port being reachable
from arbitrary network positions is a NERC CIP-005 R1 violation — the
Electronic Security Perimeter is supposed to confine 2404/tcp to the
substation control LAN.

This check is a layer-3 reachability assertion. It complements
IEC104-1.1 (which checks AUTH at layer 7) by checking ROUTING/FIREWALL
at layer 3.

Verdict:
  PASS — TCP/2404 not reachable from the audit source
  WARN (FAIL) — port open from the audit source IP
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check
from kryon.tools.ot.iec104_probe import iec104_probe


class _Iec104_21Check:
    control_id = "IEC104-2.1"
    control_title = "IEC 60870-5-104 perimeter reachability (NERC CIP-005 R1)"
    section = "IEC104-2"
    severity = "HIGH"
    remediation_static = (
        "Restrict 2404/tcp to the substation control LAN at the "
        "perimeter firewall. NERC CIP-005 R1: the Electronic Security "
        "Perimeter is the boundary; SCADA ports must not traverse it "
        "without explicit allow-rules. If the audit source IS on the "
        "control LAN, document that fact in the engagement letter and "
        "this finding becomes informational."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        result = iec104_probe(ctx.host, port=2404, test_link_alive=False)
        elapsed_ms = int((time.time() - t0) * 1000)

        if not result.reachable:
            verdict = "PASS"
            stdout = (
                f"TCP/2404 unreachable on {ctx.host} from the audit "
                f"source — perimeter firewall is doing its job. "
                f"({result.error})"
            )
        else:
            verdict = "FAIL"
            stdout = (
                f"TCP/2404 OPEN on {ctx.host} from the audit source. "
                f"Confirm whether the source IP is supposed to be inside "
                f"the Electronic Security Perimeter; if not, this is a "
                f"NERC CIP-005 R1 violation."
            )

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="iec104_probe(host, port=2404).reachable",
            evidence_stdout=stdout,
            evidence_stderr="",
            evidence_parsed={
                "reachable": result.reachable,
                "responds_to_iec104": result.responds_to_iec104,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=elapsed_ms,
            host=ctx.host,
            run_id="",
        )


CHECK = _Iec104_21Check()
register_check(CHECK)
