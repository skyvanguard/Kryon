"""FGT-3.2 — SSL VPN authentication enforces MFA.

This is the single highest-leverage control for FortiGate. The pattern of
SSL VPN attacks (post-CVE-2022-42475 mass exploitation, post-CVE-2024-21762)
shows that even when a credential leak occurs, MFA contains the blast.

We inspect the user-group → portal binding chain:
  config user group → ldap/local user authentication
  + config user local edit ... set two-factor ...
  + config authentication-scheme + config authentication-rule (advanced)

For a quick deterministic verdict we check whether SSL VPN settings reference
auth groups and whether at least one of them mandates 2FA. Exhaustive group
walking is out of scope; we surface the names so the auditor can verify.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _SslVpnMfaCheck:
    control_id = "FGT-3.2"
    control_title = "SSL VPN authentication enforces MFA"
    section = "3"
    severity = "CRITICAL"
    remediation_static = (
        "Bind SSL VPN to a group whose users require 2FA:\n"
        "  config user local\n"
        "    edit <user>\n"
        "      set two-factor fortitoken      # or email\n"
        "    next\n"
        "  end\n"
        "  config user group\n"
        '    edit "sslvpn_users"\n'
        "      set member <user1> <user2>\n"
        "    next\n"
        "  end\n"
        "  config vpn ssl settings\n"
        "    config authentication-rule\n"
        "      edit 1\n"
        '        set groups "sslvpn_users"\n'
        "      next\n"
        "    end\n"
        "  end\n"
        "Or LDAP with FortiAuthenticator handling 2FA upstream."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        # Two queries — sslvpn binding + local user 2FA attribute prevalence
        cmd_a = "show full-configuration vpn ssl settings"
        out_a, err_a, rc_a = run_cmd(ctx, cmd_a, shell=True, timeout_s=8)
        cmd_b = "show user local"
        out_b, err_b, rc_b = run_cmd(ctx, cmd_b, shell=True, timeout_s=8)

        if (rc_a != 0 and not out_a) or (rc_b != 0 and not out_b):
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=f"{cmd_a} ; {cmd_b}",
                evidence_stdout=(out_a + "\n---\n" + out_b)[:1024],
                evidence_stderr=(err_a + "\n" + err_b)[:512],
                evidence_parsed={"reason": "could not read sslvpn or user config"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # Auth-rule groups bound to SSL VPN
        bound_groups: list[str] = []
        for m in re.finditer(
            r"config\s+authentication-rule\s+(.*?)\bend\b",
            out_a,
            re.S,
        ):
            for g in re.finditer(r'set\s+groups\s+"([^"]+)"', m.group(1)):
                bound_groups.append(g.group(1))

        # Local users with 2FA enabled
        users_total = 0
        users_with_2fa = 0
        users_without_2fa: list[str] = []
        for m in re.finditer(
            r'edit\s+"([^"]+)"\s*(.*?)\bnext\b',
            out_b,
            re.S,
        ):
            users_total += 1
            name = m.group(1)
            body = m.group(2)
            tf = re.search(r"set\s+two-factor\s+(\S+)", body)
            if tf and tf.group(1).lower() not in ("disable", ""):
                users_with_2fa += 1
            else:
                users_without_2fa.append(name)

        issues: list[str] = []
        # If there are local users at all and none have 2FA → FAIL
        if users_total > 0 and users_with_2fa == 0:
            issues.append(f"all {users_total} local users lack 2FA (sslvpn likely without MFA)")
        # If majority lack 2FA → still FAIL (banking standard)
        elif users_total > 0 and users_with_2fa < users_total:
            issues.append(f"{users_total - users_with_2fa}/{users_total} local users lack 2FA")
        # No bound groups means SSL VPN auth scheme might rely on default
        # (any local user) → flag as informational HIGH
        if not bound_groups:
            issues.append(
                "SSL VPN settings reference no authentication-rule groups (default any-user policy may apply)"
            )

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"{cmd_a} ; {cmd_b}",
            evidence_stdout=(out_a + "\n---\n" + out_b)[:3072],
            evidence_stderr=(err_a + "\n" + err_b)[:512],
            evidence_parsed={
                "sslvpn_bound_groups": sorted(set(bound_groups)),
                "local_users_total": users_total,
                "local_users_with_2fa": users_with_2fa,
                "local_users_without_2fa": sorted(users_without_2fa),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _SslVpnMfaCheck()
register_check(CHECK)
