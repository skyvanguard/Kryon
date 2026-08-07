"""PVE-3.2 — API token hygiene.

Proxmox API tokens live in /etc/pve/priv/token.cfg and map to users.
Common banking-audit findings:
  - token file readable beyond pve group (644 or world-readable)
  - token assigned to root@pam without privilege separation
  - tokens with no expiry (eternal) — prohibited by banking policy
  - 0 tokens defined on a cluster that exposes an API to CI/CD
    (often masks usage of root password in automation, also bad)
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _ApiTokenHygieneCheck:
    control_id = "PVE-3.2"
    control_title = "Proxmox API tokens follow least-privilege + expiry"
    section = "3"
    severity = "HIGH"
    remediation_static = (
        "Store tokens under a dedicated non-root realm user: "
        "`pveum user add ci@pve --password ...`. "
        "Issue token with privsep: "
        "`pveum user token add ci@pve ciops --privsep 1 --expire <unix-ts>`. "
        "Enforce chmod 640 root:www-data on /etc/pve/priv/token.cfg. "
        "Rotate tokens yearly."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        stat_cmd = "stat -c '%a %U %G' /etc/pve/priv/token.cfg 2>/dev/null"
        cat_cmd = "cat /etc/pve/priv/token.cfg 2>/dev/null"
        s_out, s_err, s_rc = run_cmd(ctx, stat_cmd, shell=True, timeout_s=4)
        t_out, t_err, t_rc = run_cmd(ctx, cat_cmd, shell=True, timeout_s=4)

        issues: list[str] = []
        parsed: dict = {}

        if s_rc == 0:
            m = re.match(r"(\d+)\s+(\S+)\s+(\S+)", s_out)
            if m:
                mode, owner, group = m.groups()
                parsed["mode"] = mode
                parsed["owner"] = owner
                parsed["group"] = group
                # World-readable or group other than www-data / root is a finding
                if mode and len(mode) >= 3 and int(mode[-1]) != 0:
                    issues.append(f"token.cfg world-permissions != 0 (mode {mode})")
                if group not in ("www-data", "root"):
                    issues.append(f"token.cfg group={group} (expect www-data/root)")
        else:
            # No file present typically means no tokens defined.
            parsed["mode"] = None
            parsed["file_absent"] = True

        # Parse tokens. Format per line: `user@realm!tokenid 0 <comment>`
        # or `<user>!<tokenid>:<privsep>:<expire>:<comment>:`
        total = 0
        no_expiry = 0
        root_tokens = 0
        privsep_off = 0
        for line in t_out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total += 1
            # Heuristic: privsep and expire are columns 2 and 3 in ':' format
            parts = line.split(":")
            if len(parts) >= 3:
                try:
                    if int(parts[1]) == 0:
                        privsep_off += 1
                except ValueError:
                    pass
                try:
                    exp = int(parts[2]) if parts[2] else 0
                    if exp == 0:
                        no_expiry += 1
                except ValueError:
                    no_expiry += 1
            if line.startswith("root@pam!"):
                root_tokens += 1

        parsed["tokens_total"] = total
        parsed["tokens_no_expiry"] = no_expiry
        parsed["tokens_root_pam"] = root_tokens
        parsed["tokens_privsep_off"] = privsep_off

        if no_expiry:
            issues.append(f"{no_expiry} token(s) with no expiry")
        if root_tokens:
            issues.append(f"{root_tokens} token(s) bound to root@pam")
        if privsep_off:
            issues.append(f"{privsep_off} token(s) with privsep=0 (inherits full perms)")

        if total == 0:
            # Not automatically bad — but we report INFO-style
            parsed["advisory"] = "No API tokens defined. Verify no automation uses root password."

        verdict = "PASS" if not issues else "FAIL"
        parsed["issues"] = sorted(issues)

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"{stat_cmd} ; {cat_cmd}",
            evidence_stdout=(f"stat: {s_out}\n\nfile excerpt:\n{t_out[:1024]}")[:2048],
            evidence_stderr=(s_err + "\n" + t_err)[:512],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _ApiTokenHygieneCheck()
register_check(CHECK)
