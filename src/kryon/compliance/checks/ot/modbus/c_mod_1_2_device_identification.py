"""F84.1 — Modbus check 1.2: Device identification disclosure.

PCI-DSS adjacent: "Information disclosed by services" (cf. CIS 2.x).
Modbus function 0x2B / MEI 0x0E "Read Device Identification" returns
vendor / product / firmware-revision strings without authentication.
For asset-management hygiene this is convenient; for an attacker
fingerprinting a target before exploiting, it's a free intel gift.

The check is non-invasive — we just READ the identification. It's
strictly informational: high-severity sites should not respond to MEI
0x0E from arbitrary sources, but the response itself doesn't grant
control. Verdict reflects that nuance.

Verdict:
  WARN (encoded as N/A here) — vendor / product / revision returned;
       operator must confirm the source IP that issued the probe is
       allowlisted (otherwise anyone on the network can fingerprint).
  PASS — device rejected MEI 0x0E or returned no objects (older PLC
       that never implemented the spec — fine).
  PASS — port unreachable (most defensive posture).
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check
from kryon.tools.ot.modbus_scan import modbus_scan


class _Mod12Check:
    control_id = "MOD-1.2"
    control_title = "Modbus device identification (MEI 0x0E) disclosure"
    section = "MOD-1"
    severity = "MEDIUM"
    remediation_static = (
        "Confirm that the source of `modbus_scan` was an allowlisted "
        "engineering workstation. If MEI 0x0E responded to an arbitrary "
        "address, restrict 502/tcp at the firewall or deploy a Modbus "
        "proxy (Tofino, Bayshore) that drops fc=0x2B from non-management "
        "sources."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        result = modbus_scan(ctx.host, port=502, unit_id=1)
        elapsed_ms = int((time.time() - t0) * 1000)

        if not result.reachable:
            verdict = "PASS"
            stdout = f"port 502 unreachable on {ctx.host}: {result.error}"
        elif not result.device_identification:
            verdict = "PASS"
            stdout = (
                f"Device on {ctx.host}:502 did not return MEI 0x0E objects — "
                "either older PLC without the feature or the device "
                "explicitly suppresses it."
            )
        else:
            verdict = "FAIL"
            ident = ", ".join(
                f"{k}={v!r}" for k, v in result.device_identification.items()
            )
            stdout = (
                f"Device on {ctx.host}:502 disclosed identity to anonymous "
                f"MEI 0x0E probe: {ident}. This is fingerprintable from any "
                "network position with reachability."
            )

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="modbus_scan(host).device_identification",
            evidence_stdout=stdout,
            evidence_stderr="",
            evidence_parsed={
                "reachable": result.reachable,
                "device_identification": result.device_identification,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=elapsed_ms,
            host=ctx.host,
            run_id="",
        )


CHECK = _Mod12Check()
register_check(CHECK)
