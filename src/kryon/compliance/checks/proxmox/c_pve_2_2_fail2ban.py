"""PVE-2.2 — Brute-force protection (fail2ban) active on the node.

The Proxmox web UI (TCP 8006) and SSH (22) are prime credential brute-force
targets. fail2ban (or an equivalent) should be active to throttle repeated
auth failures. Proxmox ships a `proxmox` fail2ban filter for /var/log/daemon.log.

FAIL if fail2ban is not active. ERROR if systemctl is unavailable.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _Fail2banCheck:
    control_id = "PVE-2.2"
    control_title = "Brute-force protection (fail2ban) active"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Install and enable fail2ban with a Proxmox jail:\n"
        "  apt install fail2ban\n"
        "  # /etc/fail2ban/jail.d/proxmox.conf: enable a jail on the pveproxy /\n"
        "  # daemon.log 'authentication failure' pattern + the sshd jail.\n"
        "  systemctl enable --now fail2ban"
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "systemctl is-active fail2ban 2>/dev/null || true"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=5)

        status = out.strip()
        if not status and rc != 0:
            return self._result("ERROR", cmd, out, err, {"reason": "systemctl unavailable"}, t0, ctx)

        verdict = "PASS" if status == "active" else "FAIL"
        return self._result(verdict, cmd, out, err, {"fail2ban_status": status or "not-installed"}, t0, ctx)

    def _result(self, verdict, cmd, out, err, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:1024],
            evidence_stderr=err[:512],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _Fail2banCheck()
register_check(CHECK)
