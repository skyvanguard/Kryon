"""F84.1 — Modbus check 1.1: Anonymous read access on Modbus/TCP.

IEC 62443-3-3 SR 1.1 (Identification and Authentication Control) requires
that all communicating entities be authenticated. Modbus/TCP without an
overlay (TLS, IPsec, RADIUS-style proxy) violates this categorically.

This check probes function 0x01 (Read Coils) and 0x03 (Read Holding
Registers) without authentication. If EITHER succeeds, the device is
exposed.

Verdict:
  FAIL — any anonymous read succeeded
  PASS — both reads rejected with exception code OR target unreachable
         on port 502 (controller not exposed)
  N/A  — TCP reachable but neither response is parseable (proprietary
         non-Modbus service squatting on port 502)
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check
from kryon.tools.ot.modbus_scan import modbus_scan


class _Mod11Check:
    control_id = "MOD-1.1"
    control_title = "Modbus/TCP anonymous read access (IEC 62443 SR 1.1)"
    section = "MOD-1"
    severity = "CRITICAL"
    remediation_static = (
        "Modbus/TCP has no native authentication. Mitigations (in order of "
        "preference): (a) move the controller behind a Modbus-aware "
        "firewall (Tofino, Bayshore) that enforces a per-source allowlist "
        "for function codes; (b) deploy mTLS via stunnel between PLC and "
        "engineering workstation; (c) at minimum, restrict 502/tcp to a "
        "/30 management VLAN that only the SCADA HMI can reach."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        result = modbus_scan(ctx.host, port=502, unit_id=1)
        elapsed_ms = int((time.time() - t0) * 1000)

        if not result.reachable:
            verdict = "PASS"
            stdout = f"port 502 unreachable on {ctx.host}: {result.error}"
        elif result.has_unauth_exposure:
            verdict = "FAIL"
            modes = []
            if result.unauth_read_coils:
                modes.append("Read Coils (0x01)")
            if result.unauth_read_holding:
                modes.append("Read Holding Registers (0x03)")
            stdout = (
                f"Modbus/TCP responded to anonymous reads on {ctx.host}:502 "
                f"with unit_id=1 — exposed via: {', '.join(modes)}."
            )
            if result.device_identification:
                ident = ", ".join(f"{k}={v!r}" for k, v in result.device_identification.items())
                stdout += f" Device: {ident}."
        else:
            verdict = "PASS"
            stdout = (
                f"Port 502 open but anonymous reads rejected by {ctx.host}. "
                "Confirm the access controls separately (per-source allowlist?)."
            )

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="modbus_scan(host, port=502, unit_id=1)",
            evidence_stdout=stdout,
            evidence_stderr="",
            evidence_parsed={
                "reachable": result.reachable,
                "unauth_read_coils": result.unauth_read_coils,
                "unauth_read_holding": result.unauth_read_holding,
                "device_identification": result.device_identification,
                "response_unit_ids": list(result.response_unit_ids),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=elapsed_ms,
            host=ctx.host,
            run_id="",
        )


CHECK = _Mod11Check()
register_check(CHECK)
