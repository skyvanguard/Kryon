"""PVE-3.1 — TFA / 2FA enforced for privileged realms.

Banking compliance (SIB/BCP Resolución 06/2020 art. 15; PCI-DSS 8.4)
requires MFA for all privileged admin access. In Proxmox the TFA
configuration lives in /etc/pve/domains.cfg (per-realm default-tfa) and
per-user in /etc/pve/user.cfg (tfa field).

We flag:
  - default-tfa unset at realm level for pam/pve realms
  - root@pam without per-user TFA
  - any user with `enable 1` and no TFA binding
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _TfaEnforcedCheck:
    control_id = "PVE-3.1"
    control_title = "Multi-factor auth enforced for privileged Proxmox users"
    section = "3"
    severity = "CRITICAL"
    remediation_static = (
        "Web UI → Datacenter → Realm → edit realm → Default TFA: TOTP. "
        "Per-user: Datacenter → Permissions → Users → TFA column must "
        "show a method. Enforce on root@pam first. "
        "CLI reference: `pveum user modify root@pam --keys ...`."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        domains_cmd = "cat /etc/pve/domains.cfg 2>/dev/null"
        user_cmd = "cat /etc/pve/user.cfg 2>/dev/null"
        d_out, d_err, d_rc = run_cmd(ctx, domains_cmd, shell=True, timeout_s=5)
        u_out, u_err, u_rc = run_cmd(ctx, user_cmd, shell=True, timeout_s=5)

        if d_rc != 0 and u_rc != 0:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=f"{domains_cmd} ; {user_cmd}",
                evidence_stdout=d_out[:512],
                evidence_stderr=(d_err + "\n" + u_err)[:512],
                evidence_parsed={"reason": "could not read pve config"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        issues: list[str] = []

        # Realm-level: look for blocks like `pam: pam` then keys.
        realm_tfa: dict[str, bool] = {}
        for realm_block in re.split(r"\n\n+", d_out):
            m = re.search(r"^(pam|pve):\s*(\S+)", realm_block, re.M)
            if not m:
                continue
            realm_name = m.group(2)
            has_default_tfa = bool(re.search(r"default-tfa\s+", realm_block))
            realm_tfa[realm_name] = has_default_tfa
            if not has_default_tfa:
                issues.append(f"realm {realm_name!r} has no default-tfa")

        # Per-user: user.cfg format is `user:uid:enable:...:tfa:...`
        user_tfa: dict[str, bool] = {}
        admin_no_tfa: list[str] = []
        for line in u_out.splitlines():
            if not line.startswith("user:"):
                continue
            parts = line.split(":")
            if len(parts) < 9:
                continue
            uid = parts[1]
            enable = parts[3] or "0"
            tfa = parts[8] if len(parts) > 8 else ""
            user_tfa[uid] = bool(tfa.strip())
            if enable == "1" and not tfa.strip():
                # Flag only admin-class accounts. We heuristically treat
                # any *@pam or *@pve as privileged for a Proxmox node.
                if uid.endswith("@pam") or uid.endswith("@pve"):
                    admin_no_tfa.append(uid)

        if admin_no_tfa:
            issues.append(
                f"{len(admin_no_tfa)} privileged users without TFA: "
                + ", ".join(sorted(admin_no_tfa)[:5])
                + ("…" if len(admin_no_tfa) > 5 else "")
            )

        # root@pam — always a must.
        if "root@pam" in user_tfa and not user_tfa["root@pam"]:
            issues.append("root@pam has no TFA binding")

        verdict = "PASS" if not issues else "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"{domains_cmd} ; {user_cmd}",
            evidence_stdout=(
                f"=== domains.cfg realm-tfa ===\n{realm_tfa}\n\n=== users without tfa (first 5) ===\n{admin_no_tfa[:5]}"
            )[:2048],
            evidence_stderr="",
            evidence_parsed={
                "realm_tfa": realm_tfa,
                "admin_users_no_tfa": sorted(admin_no_tfa),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _TfaEnforcedCheck()
register_check(CHECK)
