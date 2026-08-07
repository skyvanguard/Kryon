"""XEN-1.1 — dom0 SSH permits key-based auth only (no passwords).

The Xen control domain (dom0) is the single point of control for every VM.
Password SSH exposes it to brute force; key-only auth is the baseline.
Checked via the effective sshd config (`sshd -T`).

FAIL if PasswordAuthentication is yes. ERROR if the sshd config can't be read
(SSH not enabled on dom0, or not a Xen host).
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd


class _SshKeyOnlyCheck:
    control_id = "XEN-1.1"
    control_title = "dom0 SSH key-based authentication only"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Disable password SSH on dom0 in /etc/ssh/sshd_config:\n"
        "  PasswordAuthentication no\n"
        "Distribute admin public keys first, then `systemctl restart sshd`."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "sshd -T 2>/dev/null | grep -iE '^passwordauthentication' || true"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if not out.strip():
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="could not read sshd config")

        password_auth = "passwordauthentication yes" in out.lower()
        verdict = "FAIL" if password_auth else "PASS"
        return make_result(
            check=self,
            verdict=verdict,
            cmd=cmd,
            out=out,
            err=err,
            parsed={"password_auth": password_auth},
            t0=t0,
            ctx=ctx,
        )


CHECK = _SshKeyOnlyCheck()
register_check(CHECK)
