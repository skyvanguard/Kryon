"""PCI-DSS v4 control 8.3.6 — Minimum password complexity.

PCI v4.0.1 requires:
  - PASS_MIN_LEN >= 12 (up from v3.2.1's 7)
  - Mix of alphabetic and numeric at minimum (pwquality minclass >= 2,
    we require >= 3 for a reasonable hard-floor)

Sources checked:
  /etc/login.defs         → PASS_MIN_LEN, PASS_MAX_DAYS
  /etc/security/pwquality.conf → minlen, minclass
  /etc/pam.d/common-password   → presence of pam_pwquality directive

Verdict FAIL if either enforcement point is too weak.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _read_conf_value(text: str, key: str) -> str | None:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s+(\S+)", re.M)
    m = pattern.search(text)
    if m:
        return m.group(1)
    # pwquality uses `=` separator; login.defs uses whitespace. Try = form too.
    pattern2 = re.compile(rf"^\s*{re.escape(key)}\s*=\s*(\S+)", re.M)
    m = pattern2.search(text)
    return m.group(1) if m else None


class _C836Check:
    control_id = "8.3.6"
    control_title = "Minimum password complexity"
    section = "8"
    severity = "HIGH"
    remediation_static = (
        "Set PASS_MIN_LEN 12 in /etc/login.defs. "
        "Install libpam-pwquality and in /etc/security/pwquality.conf set "
        "minlen = 12, minclass = 3, dcredit = -1, ucredit = -1, lcredit = -1, ocredit = -1. "
        "Ensure /etc/pam.d/common-password contains a pam_pwquality line."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        logindefs_out, logindefs_err, lrc = run_cmd(
            ctx,
            ["cat", "/etc/login.defs"],
            timeout_s=5,
        )
        pwquality_out, pwquality_err, prc = run_cmd(
            ctx,
            ["cat", "/etc/security/pwquality.conf"],
            timeout_s=5,
        )
        pam_out, _, _ = run_cmd(
            ctx,
            ["cat", "/etc/pam.d/common-password"],
            timeout_s=3,
        )

        issues: list[str] = []

        login_min_len = _read_conf_value(logindefs_out, "PASS_MIN_LEN")
        if login_min_len is None:
            if lrc != 0:
                return CheckResult(
                    control_id=self.control_id,
                    control_title=self.control_title,
                    section=self.section,
                    verdict="ERROR",
                    evidence_command="cat /etc/login.defs",
                    evidence_stdout=logindefs_out,
                    evidence_stderr=logindefs_err,
                    evidence_parsed={},
                    remediation_static=self.remediation_static,
                    severity=self.severity,
                    duration_ms=int((time.time() - t0) * 1000),
                    host=ctx.host,
                    run_id="",
                )
            issues.append("PASS_MIN_LEN not set in /etc/login.defs")
        else:
            try:
                if int(login_min_len) < 12:
                    issues.append(f"PASS_MIN_LEN={login_min_len} (< 12)")
            except ValueError:
                issues.append(f"PASS_MIN_LEN unparseable: {login_min_len}")

        pwq_minlen = _read_conf_value(pwquality_out, "minlen")
        pwq_minclass = _read_conf_value(pwquality_out, "minclass")
        if prc != 0 or (pwq_minlen is None and pwq_minclass is None):
            issues.append("pwquality.conf missing or unconfigured")
        else:
            if pwq_minlen is not None:
                try:
                    if int(pwq_minlen) < 12:
                        issues.append(f"pwquality minlen={pwq_minlen} (< 12)")
                except ValueError:
                    issues.append(f"pwquality minlen unparseable: {pwq_minlen}")
            if pwq_minclass is not None:
                try:
                    if int(pwq_minclass) < 3:
                        issues.append(f"pwquality minclass={pwq_minclass} (< 3)")
                except ValueError:
                    issues.append(f"pwquality minclass unparseable: {pwq_minclass}")

        if "pam_pwquality" not in pam_out and "pam_cracklib" not in pam_out:
            issues.append("no pam_pwquality/pam_cracklib in /etc/pam.d/common-password")

        verdict = "PASS" if not issues else "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="cat /etc/login.defs ; cat /etc/security/pwquality.conf ; cat /etc/pam.d/common-password",
            evidence_stdout=(
                f"=== login.defs (PASS_MIN_LEN) ===\n"
                f"PASS_MIN_LEN={login_min_len}\n\n"
                f"=== pwquality.conf ===\n"
                f"minlen={pwq_minlen}\nminclass={pwq_minclass}\n\n"
                f"=== pam.d/common-password has pam_pwquality: "
                f"{'yes' if 'pam_pwquality' in pam_out else 'no'} ==="
            )[:4096],
            evidence_stderr=(logindefs_err + "\n" + pwquality_err)[:1024],
            evidence_parsed={
                "login_defs_pass_min_len": login_min_len,
                "pwquality_minlen": pwq_minlen,
                "pwquality_minclass": pwq_minclass,
                "pam_pwquality_present": "pam_pwquality" in pam_out,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C836Check()
register_check(CHECK)
