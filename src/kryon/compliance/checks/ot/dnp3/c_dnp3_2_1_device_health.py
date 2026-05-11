"""F84.2 — DNP3 check 2.1: Outstation health flags (IIN bits).

After confirming auth posture, this check inspects the IIN (Internal
Indications) bits returned by the outstation. Several flags indicate
operational distress that an attacker can leverage:

  - device_restart: outstation rebooted; secure session keys lost; the
                    next attacker request may bypass SAv5 if the
                    operator hasn't re-keyed.
  - device_trouble: hardware fault — degraded mode might disable
                    perimeter checks.
  - config_corrupt: config corruption — falls back to last-good or
                    factory defaults; auth may be off.
  - buffer_overflow: events queued beyond capacity — operator missing
                     alarms.

NOT a critical-severity finding because IIN bits are status, not
vulnerability. But they're operationally important and PCI-DSS adjacent
requirement 10 (logging) requires the SOC to be aware.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check
from kryon.tools.ot.dnp3_probe import dnp3_probe

_TROUBLE_FLAGS = (
    "device_restart",
    "device_trouble",
    "config_corrupt",
    "buffer_overflow",
)


class _Dnp3_21Check:
    control_id = "DNP3-2.1"
    control_title = "DNP3 outstation health (IIN trouble flags)"
    section = "DNP3-2"
    severity = "MEDIUM"
    remediation_static = (
        "Investigate any flagged trouble bit on the outstation. "
        "device_restart → re-key SAv5 immediately if it was active "
        "before the reboot. device_trouble → schedule a maintenance "
        "window and inspect physical I/O. config_corrupt → restore the "
        "last-known-good config from the engineering workstation. "
        "buffer_overflow → tighten event-class polling intervals or "
        "increase outstation event-buffer size."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        result = dnp3_probe(ctx.host, port=20000)
        elapsed_ms = int((time.time() - t0) * 1000)

        if not result.reachable or not result.responds_to_dnp3:
            verdict = "N/A"
            stdout = (
                f"Cannot evaluate outstation health on {ctx.host}: "
                f"reachable={result.reachable}, "
                f"responds_to_dnp3={result.responds_to_dnp3}."
            )
            triggered: list[str] = []
        else:
            triggered = [
                flag for flag in _TROUBLE_FLAGS
                if result.iin_bits.get(flag, False)
            ]
            if triggered:
                verdict = "FAIL"
                stdout = (
                    f"DNP3 outstation at {ctx.host}:20000 reports trouble "
                    f"IIN flags: {', '.join(triggered)}. SOC investigation "
                    "required before treating subsequent readings as "
                    "trustworthy."
                )
            else:
                verdict = "PASS"
                stdout = (
                    f"DNP3 outstation at {ctx.host}:20000 reports no "
                    "trouble IIN flags."
                )

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="dnp3_probe(host).iin_bits",
            evidence_stdout=stdout,
            evidence_stderr="",
            evidence_parsed={
                "iin_bits": result.iin_bits,
                "trouble_flags_set": triggered,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=elapsed_ms,
            host=ctx.host,
            run_id="",
        )


CHECK = _Dnp3_21Check()
register_check(CHECK)
