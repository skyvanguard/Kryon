"""F84.3 — S7 check 1.1: Anonymous S7Comm session establishment.

S7Comm v1 has no authentication. S7Comm-Plus (firmware ≥ v2.0 on
S7-1500) added access protection levels but most LATAM industrial
deployments still run plain S7Comm for legacy WinCC interop.

This check probes the canonical 3-stage handshake (TCP → COTP CR →
S7 Setup Communication). If we receive an S7 Setup Ack from any
arbitrary source IP, the PLC accepts unauthenticated sessions —
violating IEC 62443 SR 1.1 directly.

Verdict:
  FAIL — S7 session established without challenge
  PASS — port unreachable OR COTP/S7 setup rejected
  N/A  — port open but no S7 framing in response
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check
from kryon.tools.ot.s7_enum import s7_enum


class _S7_11Check:
    control_id = "S7-1.1"
    control_title = "Siemens S7Comm anonymous session (IEC 62443 SR 1.1)"
    section = "S7-1"
    severity = "CRITICAL"
    remediation_static = (
        "Activate the S7-1500 'Access Protection' feature (4 levels: "
        "full / read-only / HMI access / no access) and set a strong "
        "password per level. For S7-300/400 (no built-in auth), wrap "
        "102/tcp in a stunnel TLS tunnel and restrict source IPs at the "
        "firewall to engineering workstations only. Audit Siemens "
        "Security Advisory SSA-381581 for additional hardening guidance "
        "specific to your CPU family."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        result = s7_enum(ctx.host, port=102)
        elapsed_ms = int((time.time() - t0) * 1000)

        if not result.reachable:
            verdict = "PASS"
            stdout = f"port 102 unreachable on {ctx.host}: {result.error}"
        elif result.s7_session_established:
            verdict = "FAIL"
            stdout = (
                f"S7Comm session established without authentication on "
                f"{ctx.host}:102."
            )
            if result.module_identification:
                ident_pieces = []
                for key in ("order_code", "firmware"):
                    if key in result.module_identification:
                        ident_pieces.append(
                            f"{key}={result.module_identification[key]!r}"
                        )
                if ident_pieces:
                    stdout += " Device: " + ", ".join(ident_pieces) + "."
        elif result.cotp_connected:
            verdict = "PASS"
            stdout = (
                f"COTP connection accepted but S7 setup rejected on "
                f"{ctx.host}:102 — likely access protection enabled."
            )
        else:
            verdict = "N/A"
            stdout = (
                f"Port 102 open on {ctx.host} but COTP rejected — could "
                f"be a different ISO-on-TCP service or wrong rack/slot."
            )

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="s7_enum(host, port=102)",
            evidence_stdout=stdout,
            evidence_stderr="",
            evidence_parsed={
                "reachable": result.reachable,
                "cotp_connected": result.cotp_connected,
                "s7_session_established": result.s7_session_established,
                "module_identification": result.module_identification,
                "plc_firmware_version": result.plc_firmware_version,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=elapsed_ms,
            host=ctx.host,
            run_id="",
        )


CHECK = _S7_11Check()
register_check(CHECK)
