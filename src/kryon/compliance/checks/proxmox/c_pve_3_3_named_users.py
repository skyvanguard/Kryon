"""PVE-3.3 — Named individual admin users exist (not just shared root@pam).

If every operator logs in as `root@pam`, there is no accountability — you
can't tell who did what. Proxmox stores accounts in /etc/pve/user.cfg.

FAIL if the only enabled user is root@pam (shared-root anti-pattern).
PASS if at least one other enabled, named account exists. ERROR if
user.cfg can't be read.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

# user.cfg line: user:<userid>:<enable>:<expire>:<first>:<last>:<email>:...
_USER_RE = re.compile(r"^user:([^:]+):(\d):", re.M)


class _NamedUsersCheck:
    control_id = "PVE-3.3"
    control_title = "Named individual admin users exist (not only root@pam)"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Create per-operator accounts and stop sharing root@pam:\n"
        "  pveum user add alice@pve --comment 'Alice - infra'\n"
        "  pveum acl modify / --users alice@pve --roles Administrator\n"
        "Reserve root@pam for break-glass only; enforce 2FA (PVE-3.1) on all."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/pve/user.cfg 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read user.cfg"}, t0, ctx)

        enabled_users = [uid for uid, enable in _USER_RE.findall(out) if enable == "1"]
        named = [u for u in enabled_users if u != "root@pam"]

        verdict = "PASS" if named else "FAIL"
        return self._result(
            verdict,
            cmd,
            out,
            err,
            {"enabled_users": enabled_users, "named_non_root_users": named},
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


CHECK = _NamedUsersCheck()
register_check(CHECK)
