"""AD-3.2 — Domain password policy meets banking minimums.

Banking baseline (PCI-DSS 8.3.6 + BCP SIB): min 12 chars, complexity,
lockout after 10 failed attempts, history ≥ 24. We read `pwdProperties`
from the domain root and length/age attributes.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.active_directory._helpers import (
    ad_env,
    check_tool,
    missing_creds_error,
    tool_missing_error,
)
from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _PasswordPolicyCheck:
    control_id = "AD-3.2"
    control_title = "Domain password policy meets banking minimums (>=12 / complex / lockout)"
    section = "3"
    severity = "HIGH"
    remediation_static = (
        "Open Default Domain Policy → Computer Config → Policies → "
        "Windows Settings → Security Settings → Account Policies → "
        "Password Policy. Set: Length=12, Complexity=Enabled, "
        "History=24, MaxAge=90, MinAge=1. "
        "Lockout: threshold=10, duration=30 min, reset=30 min. "
        "gpupdate /force on all DCs."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        domain, user, pwd, dc = ad_env()
        dc = dc or ctx.host

        if not (domain and user and pwd and dc):
            return missing_creds_error(
                self.control_id, self.control_title, self.section,
                self.severity, self.remediation_static, ctx.host, t0,
            )

        if not check_tool(ctx, "ldapsearch"):
            return tool_missing_error(
                self.control_id, self.control_title, self.section,
                self.severity, self.remediation_static, ctx.host, t0,
                tool="ldapsearch", install_hint="apt install ldap-utils",
            )

        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
        cmd = (
            f"ldapsearch -x -H ldap://{dc} -D '{user}' -w '{pwd}' "
            f"-b '{base_dn}' -s base "
            f"minPwdLength minPwdAge maxPwdAge "
            f"pwdProperties pwdHistoryLength lockoutThreshold "
            f"lockoutDuration lockOutObservationWindow 2>&1"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)

        def get_int(key: str) -> int | None:
            m = re.search(rf"^{key}:\s*(-?\d+)$", out, re.M)
            return int(m.group(1)) if m else None

        min_len = get_int("minPwdLength")
        pwd_props = get_int("pwdProperties")
        history = get_int("pwdHistoryLength")
        lockout_th = get_int("lockoutThreshold")
        max_age = get_int("maxPwdAge")  # 100-ns intervals, negative

        if min_len is None:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd.replace(pwd, "***"),
                evidence_stdout=out[:1024],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "password policy attrs not returned"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        issues: list[str] = []
        # minPwdLength — banking floor 12
        if min_len < 12:
            issues.append(f"minPwdLength={min_len} (banking floor 12)")
        # pwdProperties bit 0 = complexity required (0x1 DOMAIN_PASSWORD_COMPLEX)
        if pwd_props is not None and (pwd_props & 0x1) == 0:
            issues.append("password complexity NOT required (DOMAIN_PASSWORD_COMPLEX bit off)")
        # history — banking >= 24
        if history is not None and history < 24:
            issues.append(f"pwdHistoryLength={history} (should be >=24)")
        # lockout threshold — banking <=10
        if lockout_th is None or lockout_th == 0:
            issues.append("lockoutThreshold=0 (no lockout, brute-force possible)")
        elif lockout_th > 10:
            issues.append(f"lockoutThreshold={lockout_th} (should be <=10)")
        # maxPwdAge — negative LDAP interval. |val| / 1e7 / 86400 = days.
        max_age_days: int | None = None
        if max_age is not None and max_age < 0:
            max_age_days = abs(max_age) // 10_000_000 // 86400
            if max_age_days > 90:
                issues.append(f"maxPwdAge={max_age_days}d (should be <=90)")
            elif max_age_days == 0:
                issues.append("maxPwdAge=0 (passwords never expire)")

        verdict = "PASS" if not issues else "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd.replace(pwd, "***"),
            evidence_stdout=out[:1024],
            evidence_stderr=err[:256],
            evidence_parsed={
                "minPwdLength": min_len,
                "pwdProperties": pwd_props,
                "pwdHistoryLength": history,
                "lockoutThreshold": lockout_th,
                "maxPwdAge_days": max_age_days,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _PasswordPolicyCheck()
register_check(CHECK)
