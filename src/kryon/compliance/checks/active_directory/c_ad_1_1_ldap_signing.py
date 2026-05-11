"""AD-1.1 — LDAP signing required (no unsigned binds allowed on 389/tcp).

Modern AD (post-2020 patches) enforces `LDAPServerIntegrity=2` which
rejects simple binds over cleartext 389. We probe by attempting a
simple bind to port 389 — if it succeeds, signing is NOT enforced and
credentials can be replayed over the network.

Reference: Microsoft ADV190023.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.active_directory._helpers import (
    ad_env,
    check_tool,
    missing_creds_error,
    tool_missing_error,
)
from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _LdapSigningCheck:
    control_id = "AD-1.1"
    control_title = "LDAP signing enforced (rejects unsigned binds on 389/tcp)"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "On DC: set Group Policy → Domain Controller Policy → "
        "Security Options → 'Domain controller: LDAP server signing "
        "requirements' = 'Require signing'. "
        "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\"
        "LDAPServerIntegrity = 2. Reboot or `gpupdate /force`. "
        "Coordinate — unsigned LDAP clients (legacy apps) must be upgraded first."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        domain, user, pwd, dc = ad_env()
        dc = dc or ctx.host

        if not (domain and user and pwd and dc):
            return missing_creds_error(
                self.control_id,
                self.control_title,
                self.section,
                self.severity,
                self.remediation_static,
                ctx.host,
                t0,
            )

        if not check_tool(ctx, "ldapsearch"):
            return tool_missing_error(
                self.control_id,
                self.control_title,
                self.section,
                self.severity,
                self.remediation_static,
                ctx.host,
                t0,
                tool="ldapsearch",
                install_hint="apt install ldap-utils",
            )

        # Simple bind over cleartext 389 — should FAIL if signing enforced.
        cmd = f"ldapsearch -x -H ldap://{dc}:389 -D '{user}' -w '{pwd}' -b '' -s base namingContexts 2>&1 | head -20"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)

        issues: list[str] = []
        parsed: dict = {"probe_rc": rc}

        # Clues that signing is NOT enforced:
        #   rc == 0 AND "result: 0 Success" in output
        # Clues that signing IS enforced:
        #   rc != 0 AND "Strong(er) authentication required" in err
        success_marker = "result: 0 Success" in out or "namingContexts:" in out
        signing_required_marker = (
            "Strong(er) authentication required" in out
            or "Strong(er) authentication required" in err
            or "stronger authentication" in (out + err).lower()
        )

        if success_marker and not signing_required_marker:
            issues.append("Simple bind on 389 succeeded — LDAP signing NOT enforced")
            parsed["simple_bind"] = "succeeded"
        elif signing_required_marker:
            parsed["simple_bind"] = "rejected (signing enforced)"
        else:
            # Ambiguous — connection refused, creds wrong, etc.
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:1024],
                evidence_stderr=err[:512],
                evidence_parsed={
                    "reason": "ambiguous result (bad creds / DC unreachable?)",
                    "probe_rc": rc,
                },
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        verdict = "PASS" if not issues else "FAIL"
        parsed["issues"] = sorted(issues)

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd.replace(pwd, "***"),
            evidence_stdout=out[:1024],
            evidence_stderr=err[:512],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _LdapSigningCheck()
register_check(CHECK)
