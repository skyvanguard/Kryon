"""F84.4 — IEC 60870-5-104 check 1.1: Anonymous STARTDT activation.

The base IEC 60870-5-104 protocol has zero authentication. The IEC
62351-3 overlay adds TLS but it's optional and frequently disabled
(performance overhead on low-bandwidth substation links was the
historic argument; cert management is the contemporary one).

This check sends a STARTDT activation U-frame. If the controller
responds with a STARTDT confirmation, anyone with TCP/2404 reachability
can activate the session and start receiving telemetry / send commands.

Verdict:
  FAIL — STARTDT confirmation received from arbitrary source
  PASS — port unreachable OR STARTDT rejected
  N/A  — port open but no IEC 104 framing (other service on 2404)
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check
from kryon.tools.ot.iec104_probe import iec104_probe


class _Iec104_11Check:
    control_id = "IEC104-1.1"
    control_title = "IEC 60870-5-104 anonymous STARTDT activation (IEC 62443 SR 1.1)"
    section = "IEC104-1"
    severity = "CRITICAL"
    remediation_static = (
        "Deploy the IEC 62351-3 overlay (TLS with certificate-based "
        "authentication) on the RTU. If the firmware can't speak "
        "62351-3, isolate 2404/tcp behind an IEC-104-aware firewall "
        "(Owl, Waterfall, Tofino with IEC profile) that only accepts "
        "STARTDT from the SCADA Master. NERC CIP-005 R1 expects an "
        "Electronic Security Perimeter — the RTU should not be "
        "reachable from the corporate network at all."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        result = iec104_probe(ctx.host, port=2404)
        elapsed_ms = int((time.time() - t0) * 1000)

        if not result.reachable:
            verdict = "PASS"
            stdout = f"port 2404 unreachable on {ctx.host}: {result.error}"
        elif not result.responds_to_iec104:
            verdict = "N/A"
            stdout = (
                f"Port 2404 open on {ctx.host} but the device did not "
                f"reply with IEC 60870-5-104 framing. Confirm with "
                f"`nc -v {ctx.host} 2404` and the integrator."
            )
        elif result.startdt_confirmed:
            verdict = "FAIL"
            stdout = (
                f"IEC 60870-5-104 RTU at {ctx.host}:2404 confirmed STARTDT "
                f"activation from anonymous source. Telemetry is now "
                f"flowing and command frames would be accepted."
            )
            if result.testfr_confirmed:
                stdout += " TESTFR liveness also confirmed — link is fully active."
        else:
            verdict = "PASS"
            stdout = (
                f"IEC 60870-5-104 RTU at {ctx.host}:2404 rejected STARTDT "
                f"activation — likely IP allowlist or 62351-3 in place."
            )

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="iec104_probe(host, port=2404)",
            evidence_stdout=stdout,
            evidence_stderr="",
            evidence_parsed={
                "reachable": result.reachable,
                "responds_to_iec104": result.responds_to_iec104,
                "startdt_confirmed": result.startdt_confirmed,
                "testfr_confirmed": result.testfr_confirmed,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=elapsed_ms,
            host=ctx.host,
            run_id="",
        )


CHECK = _Iec104_11Check()
register_check(CHECK)
