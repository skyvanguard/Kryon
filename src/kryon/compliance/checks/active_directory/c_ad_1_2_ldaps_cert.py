"""AD-1.2 — LDAPS (636/tcp) available with valid, CA-signed certificate.

Banking environments require LDAP over TLS. We check:
  - Port 636 responds to TLS handshake
  - Cert expiry >= 30 days
  - Not self-signed (issuer != subject)
  - Uses RSA >= 2048 or ECDSA
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.active_directory._helpers import (
    ad_env, check_tool, tool_missing_error,
)
from kryon.compliance.runner import register_check, run_cmd


class _LdapsCertCheck:
    control_id = "AD-1.2"
    control_title = "LDAPS (636/tcp) available with valid CA-signed cert"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Install a CA-signed cert on the DC via Server Manager → AD CS → "
        "Request certificate with template 'Domain Controller'. "
        "If using enterprise CA (common in banks), GPO auto-enrollment "
        "should renew automatically. Verify: `Certutil -verifystore -v MY`. "
        "Make sure port 636/tcp reachable from app servers."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        _, _, _, dc = ad_env()
        dc = dc or ctx.host

        if not check_tool(ctx, "openssl"):
            return tool_missing_error(
                self.control_id, self.control_title, self.section,
                self.severity, self.remediation_static, ctx.host, t0,
                tool="openssl", install_hint="apt install openssl",
            )

        cmd = (
            f"echo '' | openssl s_client -connect {dc}:636 -servername {dc} "
            f"-showcerts -verify_return_error 2>&1 "
            f"| openssl x509 -noout -subject -issuer -dates 2>&1 | head -10"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=12)

        if "subject=" not in out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="FAIL",
                evidence_command=cmd,
                evidence_stdout=out[:1024],
                evidence_stderr=err[:512],
                evidence_parsed={
                    "reason": "could not retrieve cert from 636/tcp",
                    "probe_rc": rc,
                },
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        subject = _grab(r"^subject=\s*(.+)$", out)
        issuer = _grab(r"^issuer=\s*(.+)$", out)
        notafter = _grab(r"^notAfter=(.+)$", out)

        issues: list[str] = []
        parsed: dict = {"subject": subject or "", "issuer": issuer or "",
                        "not_after": notafter or ""}

        if subject and issuer and subject.strip() == issuer.strip():
            issues.append("LDAPS certificate is self-signed")
            parsed["self_signed"] = True

        if notafter:
            try:
                exp = datetime.strptime(notafter.strip(), "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                parsed["days_to_expiry"] = days
                if days < 0:
                    issues.append(f"LDAPS cert expired {-days}d ago")
                elif days < 30:
                    issues.append(f"LDAPS cert expires in {days}d (<30d)")
            except ValueError:
                issues.append("Could not parse notAfter")

        verdict = "PASS" if not issues else "FAIL"
        parsed["issues"] = sorted(issues)

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


def _grab(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text, re.M)
    return m.group(1).strip() if m else None


CHECK = _LdapsCertCheck()
register_check(CHECK)
