"""PVE-7.1 — Time synchronization active.

Proxmox cluster quorum (corosync) is time-sensitive and cross-node log
correlation, TLS validation and ticket auth all depend on synchronized
clocks. Verifies NTP is enabled AND the clock is synced via timedatectl.

FAIL if NTP is off or the clock is not synchronized. ERROR if timedatectl
is unavailable.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _TimeSyncCheck:
    control_id = "PVE-7.1"
    control_title = "Time synchronization active (cluster + log correlation)"
    section = "7"
    severity = "MEDIUM"
    remediation_static = (
        "Enable time sync on every node: `timedatectl set-ntp true` "
        "(systemd-timesyncd) or install chrony and point it at a trusted NTP "
        "source. In a cluster, all nodes MUST use the same source."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "timedatectl show --property=NTP --property=NTPSynchronized 2>/dev/null; timedatectl 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=6)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "timedatectl unavailable"}, t0, ctx)

        low = out.lower()
        ntp_active = "ntp=yes" in low or "ntp service: active" in low
        synchronized = "ntpsynchronized=yes" in low or "system clock synchronized: yes" in low
        verdict = "PASS" if (ntp_active and synchronized) else "FAIL"
        return self._result(
            verdict,
            cmd,
            out,
            err,
            {"ntp_active": ntp_active, "clock_synchronized": synchronized},
            t0,
            ctx,
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


CHECK = _TimeSyncCheck()
register_check(CHECK)
