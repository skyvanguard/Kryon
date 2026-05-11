"""CIS section 2 control 2.2.8 — Brute-force protection (fail2ban).

A hardened SSH-exposed host must have a brute-force protection service
actively running. We accept either:
  - fail2ban   (most common on Debian/Ubuntu/PVE)
  - sshguard   (alternative used in some BSD-derived stacks)

Evidence: `systemctl is-active fail2ban` and `systemctl is-active sshguard`.
Verdict FAIL when neither is active; PASS when at least one is.

Closes ground-truth gap H-01 against a target like proxmox2 where SSH
is open on a public-ish interface and no brute-force guard exists.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _C228Check:
    control_id = "2.2.8"
    control_title = "Brute-force protection active (fail2ban or sshguard)"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Install and enable fail2ban: `apt-get install -y fail2ban && "
        "systemctl enable --now fail2ban`. Default Debian jail config "
        "covers sshd. Verify with `fail2ban-client status sshd`."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        f2b_out, f2b_err, _ = run_cmd(
            ctx, ["systemctl", "is-active", "fail2ban"], timeout_s=5,
        )
        sg_out, sg_err, _ = run_cmd(
            ctx, ["systemctl", "is-active", "sshguard"], timeout_s=5,
        )
        f2b_state = (f2b_out or "").strip().lower()
        sg_state = (sg_out or "").strip().lower()

        active = f2b_state == "active" or sg_state == "active"
        verdict = "PASS" if active else "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="systemctl is-active fail2ban; systemctl is-active sshguard",
            evidence_stdout=f"fail2ban: {f2b_state}\nsshguard: {sg_state}",
            evidence_stderr=(f2b_err + "\n" + sg_err)[:1024],
            evidence_parsed={
                "fail2ban_state": f2b_state,
                "sshguard_state": sg_state,
                "any_active": active,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C228Check()
register_check(CHECK)
