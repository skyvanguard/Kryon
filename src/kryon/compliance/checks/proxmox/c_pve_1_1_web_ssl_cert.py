"""PVE-1.1 — Web UI SSL certificate is CA-signed and valid.

Proxmox ships with a self-signed cert at /etc/pve/pve-ssl.pem. In banking
environments this must be replaced by a certificate from the corporate
CA (or Let's Encrypt for DMZ deployments) — browsers surfacing a "Not
Secure" banner in production is itself a compliance finding.

We read the leaf cert via openssl and flag:
  - Issuer CN == Subject CN  (self-signed)
  - Validity window expired or expiring within 30 days
  - Key size < 2048 bits (RSA) or not ecdsa
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _WebSslCertCheck:
    control_id = "PVE-1.1"
    control_title = "Web UI SSL certificate is CA-signed and not expired"
    section = "1"
    severity = "HIGH"
    remediation_static = (
        "Replace the default self-signed cert. From the Web UI → "
        "Datacenter → Certificates → Upload Custom (or ACME for public). "
        "CLI: `pvenode cert set --force <cert.pem> <key.pem>`. "
        "Ensure RSA >= 2048 bits or ECDSA P-256. Set up auto-renewal."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cert_path = "/etc/pve/local/pve-ssl.pem"
        cmd = f"openssl x509 -in {cert_path} -noout -subject -issuer -dates -pubkey 2>&1"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        issues: list[str] = []
        parsed: dict[str, str | bool | int] = {}

        if rc != 0:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "openssl failed or cert absent"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        subject = _grab(r"^subject=\s*(.+)$", out)
        issuer = _grab(r"^issuer=\s*(.+)$", out)
        nb = _grab(r"^notBefore=(.+)$", out)
        na = _grab(r"^notAfter=(.+)$", out)
        parsed["subject"] = subject or ""
        parsed["issuer"] = issuer or ""
        parsed["not_before"] = nb or ""
        parsed["not_after"] = na or ""

        if subject and issuer and subject.strip() == issuer.strip():
            issues.append("Certificate is self-signed (subject == issuer)")
            parsed["self_signed"] = True

        if na:
            try:
                exp = datetime.strptime(na.strip(), "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc,
                )
                now = datetime.now(timezone.utc)
                days = (exp - now).days
                parsed["days_to_expiry"] = days
                if days < 0:
                    issues.append(f"Certificate expired {-days} days ago")
                elif days < 30:
                    issues.append(f"Certificate expires in {days} days (<30d threshold)")
            except ValueError:
                issues.append("Could not parse notAfter date")

        # RSA key length sniff from PEM output — `openssl x509 -pubkey` emits
        # a SubjectPublicKeyInfo PEM; we re-run modulus to get size.
        mod_cmd = f"openssl x509 -in {cert_path} -noout -modulus 2>/dev/null | wc -c"
        mod_out, _, _ = run_cmd(ctx, mod_cmd, shell=True, timeout_s=5)
        try:
            # "Modulus=..." is 513 hex chars for 2048-bit RSA + newline.
            mod_len = int(mod_out.strip()) if mod_out.strip().isdigit() else 0
            # Rough floor check; EC keys bypass this (shorter modulus output).
            if 0 < mod_len < 520:
                bits_est = (mod_len - 8) * 4  # approx
                if bits_est < 2048:
                    issues.append(f"RSA key < 2048 bits (~{bits_est})")
                    parsed["rsa_bits_estimate"] = bits_est
        except ValueError:
            pass

        verdict = "PASS" if not issues else "FAIL"
        parsed["issues"] = sorted(issues)

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


def _grab(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text, re.M)
    return m.group(1).strip() if m else None


CHECK = _WebSslCertCheck()
register_check(CHECK)
