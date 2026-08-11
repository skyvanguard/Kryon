"""PCI-DSS v4.0.1 control 8.4.3 — MFA for all remote network access into the CDE.

Mandatory since 2025-03-31. Verifies that SSH remote access enforces
multi-factor authentication, via either:
  - ``AuthenticationMethods`` in sshd_config chaining 2+ factors
    (e.g. ``publickey,keyboard-interactive``), OR
  - a PAM MFA module in /etc/pam.d/sshd (google-authenticator, oath,
    u2f/fido2, yubico).

FIDO2 / WebAuthn (pam_u2f / pam_fido2) is flagged as **phishing-resistant**.

Honest scope: N/A when no SSH service / config is readable (a scanner can't
assert MFA it can't see). FAIL only when SSH is present and single-factor.
Covers the SSH remote-access path; VPN/RDP MFA is out of band (manual).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_PHISHING_RESISTANT = ("pam_u2f", "pam_fido2")
_MFA_PAM_MODULES = ("pam_google_authenticator", "pam_oath", "pam_u2f", "pam_fido2", "pam_yubico")


class _C843Check:
    control_id = "8.4.3"
    control_title = "MFA for remote network access to the CDE"
    section = "8"
    # CRITICAL: 4.0.1 mandatorio — phishing-resistant MFA on CDE remote access;
    # weak/absent MFA is a top breach vector.
    severity = "CRITICAL"
    remediation_static = (
        "Enforce MFA on SSH: in /etc/ssh/sshd_config set "
        "`AuthenticationMethods publickey,keyboard-interactive` and configure a PAM MFA "
        "module in /etc/pam.d/sshd. For phishing-resistant MFA (PCI-DSS v4.0.1 8.4.3 / "
        "8.5.1), use FIDO2 / WebAuthn via pam_u2f or pam_fido2 (hardware security keys)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        sshd_out, sshd_err, sshd_rc = run_cmd(ctx, ["cat", "/etc/ssh/sshd_config"], timeout_s=5)
        pam_out, _, pam_rc = run_cmd(ctx, ["cat", "/etc/pam.d/sshd"], timeout_s=3)

        # No SSH service / config unreadable → not verifiable, not a failure.
        if sshd_rc != 0 and pam_rc != 0:
            return self._result(
                "N/A",
                "cat /etc/ssh/sshd_config ; cat /etc/pam.d/sshd",
                "no SSH service or config not readable",
                sshd_err[:512],
                {"reason": "no SSH service / config not readable"},
                t0,
                ctx,
            )

        # AuthenticationMethods chaining 2+ factors.
        am = None
        m = re.search(r"^\s*AuthenticationMethods\s+(.+)$", sshd_out, re.MULTILINE | re.IGNORECASE)
        if m:
            am = m.group(1).strip()
        am_multifactor = bool(am) and "," in am and "none" not in am.lower()

        # PAM MFA modules (uncommented lines only).
        pam_mods: list[str] = []
        phishing_resistant = False
        for line in pam_out.splitlines():
            s = line.strip()
            if s.startswith("#") or not s:
                continue
            for mod_name in _MFA_PAM_MODULES:
                if mod_name in s:
                    pam_mods.append(mod_name)
                    if mod_name in _PHISHING_RESISTANT:
                        phishing_resistant = True

        has_mfa = am_multifactor or bool(pam_mods)
        parsed = {
            "authentication_methods": am,
            "auth_methods_multifactor": am_multifactor,
            "pam_mfa_modules": sorted(set(pam_mods)),
            "phishing_resistant": phishing_resistant,
        }
        return self._result(
            "PASS" if has_mfa else "FAIL",
            "cat /etc/ssh/sshd_config ; cat /etc/pam.d/sshd",
            f"AuthenticationMethods={am}\nPAM MFA modules={sorted(set(pam_mods))}\nphishing_resistant={phishing_resistant}",
            "",
            parsed,
            t0,
            ctx,
        )

    def _result(self, verdict, cmd, stdout, stderr, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=stdout[:4096],
            evidence_stderr=stderr[:1024],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C843Check()
register_check(CHECK)
