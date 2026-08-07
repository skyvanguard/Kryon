"""F84.2 — DNP3 check 1.1: Unauthenticated read access.

DNP3 base protocol has zero authentication. Secure Authentication v5
(SAv5) added in IEEE 1815-2012 closes the gap but real LATAM utility
deployments rarely enable it (legacy RTU interop, RBAC complexity).

This check sends a Read Class 0 request (function 0x01, group 60 var 1)
and inspects the response. If the device replies with function 0x81
(Read response) without first challenging us with 0x83 (SAv5
Authentication Challenge), it's exposed.

Verdict:
  FAIL — device responded with Read response (no SAv5 challenge)
  PASS — device challenged for SAv5 credentials OR port unreachable
  N/A  — TCP reachable but no DNP3 framing in response (other service)

References:
  - IEC 62443-3-3 SR 1.1 (Identification and authentication)
  - NERC CIP-005 R1 (Electronic Security Perimeter)
  - NERC CIP-007 R5 (System access control)
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check
from kryon.tools.ot.dnp3_probe import dnp3_probe


class _Dnp3_11Check:
    control_id = "DNP3-1.1"
    control_title = "DNP3 unauthenticated read access (IEC 62443 SR 1.1)"
    section = "DNP3-1"
    severity = "CRITICAL"
    remediation_static = (
        "Enable DNP3 Secure Authentication v5 (SAv5) on the outstation. "
        "If the firmware doesn't support SAv5 (typical for RTUs > 10 yr "
        "old), wrap the link in a TLS tunnel (stunnel, IPsec) and "
        "restrict 20000/tcp to the SCADA front-end /30 only. NERC CIP-007 "
        "R5 also expects logging of all DNP3 sessions — confirm syslog "
        "exports the connection events to the SOC."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        result = dnp3_probe(ctx.host, port=20000)
        elapsed_ms = int((time.time() - t0) * 1000)

        if not result.reachable:
            verdict = "PASS"
            stdout = f"port 20000 unreachable on {ctx.host}: {result.error}"
        elif not result.responds_to_dnp3:
            verdict = "N/A"
            stdout = (
                f"Port 20000 open on {ctx.host} but the response does not "
                f"have DNP3 framing — different service squatting on the "
                f"port? Confirm with `nc -v {ctx.host} 20000` manually."
            )
        elif result.has_unauth_exposure:
            verdict = "FAIL"
            stdout = (
                f"DNP3 outstation at {ctx.host}:20000 (address "
                f"{result.outstation_address}) responded to anonymous Read "
                f"Class 0 without SAv5 challenge. ALL outstation data is "
                f"readable from any source with TCP reachability."
            )
            if result.iin_bits.get("device_restart"):
                stdout += (
                    " Device also reports DEVICE_RESTART IIN bit — recently "
                    "rebooted, may have lost secure session state."
                )
        else:
            verdict = "PASS"
            stdout = (
                f"DNP3 outstation at {ctx.host}:20000 challenged with SAv5 "
                f"authentication request — credentials enforced."
            )

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="dnp3_probe(host, port=20000)",
            evidence_stdout=stdout,
            evidence_stderr="",
            evidence_parsed={
                "reachable": result.reachable,
                "responds_to_dnp3": result.responds_to_dnp3,
                "outstation_address": result.outstation_address,
                "secure_auth_v5_active": result.secure_auth_v5_active,
                "iin_bits": result.iin_bits,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=elapsed_ms,
            host=ctx.host,
            run_id="",
        )


CHECK = _Dnp3_11Check()
register_check(CHECK)
