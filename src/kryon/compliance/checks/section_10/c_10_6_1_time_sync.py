"""PCI-DSS v4 control 10.6.1 — Time synchronization.

System clocks and time must be synchronized using time-sync technology
(NTP: chrony, ntpd, or systemd-timesyncd). Consistent time is what makes
audit logs (Req 10) correlatable across systems.

Verifies via `timedatectl`: PASS when NTP is enabled AND the clock is
synchronized. FAIL otherwise. ERROR if timedatectl is unavailable.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _C1061Check:
    control_id = "10.6.1"
    control_title = "Time synchronization (NTP)"
    section = "10"
    severity = "MEDIUM"
    remediation_static = (
        "Enable a time-sync service and point it at trusted sources. "
        "`timedatectl set-ntp true` (systemd-timesyncd) or install chrony "
        "(`systemctl enable --now chronyd`) with `server <ntp-host> iburst` in "
        "/etc/chrony/chrony.conf. Verify with `timedatectl` (PCI-DSS 10.6.1)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        out, err, rc = run_cmd(
            ctx,
            ["timedatectl", "show", "--property=NTP", "--property=NTPSynchronized"],
            timeout_s=5,
        )
        # Fallback to the human-readable form on older timedatectl.
        if rc != 0 or ("ntp" not in out.lower()):
            out2, err2, rc2 = run_cmd(ctx, ["timedatectl"], timeout_s=5)
            if rc2 == 0 and out2.strip():
                out, err, rc = out2, err2, rc2

        if rc != 0 and not out.strip():
            return self._result("ERROR", out, err, {"reason": "timedatectl unavailable"}, t0, ctx)

        low = out.lower()
        ntp_active = "ntp=yes" in low or "ntp service: active" in low
        synchronized = "ntpsynchronized=yes" in low or "system clock synchronized: yes" in low
        verdict = "PASS" if (ntp_active and synchronized) else "FAIL"

        return self._result(
            verdict,
            out,
            err,
            {"ntp_active": ntp_active, "clock_synchronized": synchronized},
            t0,
            ctx,
        )

    def _result(self, verdict, stdout, stderr, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="timedatectl show --property=NTP --property=NTPSynchronized",
            evidence_stdout=stdout[:4096],
            evidence_stderr=stderr[:1024],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C1061Check()
register_check(CHECK)
