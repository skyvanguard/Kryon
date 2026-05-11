"""FGT-5.2 — FortiGuard licences (AV / IPS / WebFilter / AppCtrl) are valid.

`diagnose autoupdate versions` reports each subscription's last-update
timestamp. Expired AV/IPS feeds = stale signatures = the IPS/AV is
operationally useless, even when policies still apply.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

# We require these subscriptions for any policy that uses UTM features.
_REQUIRED_FEATURES = ("AV", "IPS", "App Detection", "Web Filtering")


class _FortiGuardLicensesCheck:
    control_id = "FGT-5.2"
    control_title = "FortiGuard subscriptions (AV/IPS/WebFilter/AppCtrl) are valid"
    section = "5"
    severity = "HIGH"
    remediation_static = (
        "Renew the FortiGuard bundle or à-la-carte feeds via FortiCare:\n"
        "  - Validate contract: `get system fortiguard`\n"
        "  - Force refresh: `execute update-now`\n"
        "  - If subscription expired, the service still loads the LAST signature\n"
        "    set but does not receive new IOCs. New CVEs go undetected.\n"
        "Pair with a renewal calendar reminder 90 days before expiry."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "get system fortiguard"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)

        if rc != 0 and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not read fortiguard status"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # Look for "AV Definitions Update Status   : Last Update Attempt: <date>"
        # and "Last Update Result : Success"
        # `get system fortiguard` sometimes returns flat key:value pairs.
        statuses: dict[str, str] = {}
        for line in out.splitlines():
            ls = line.strip()
            for feat in _REQUIRED_FEATURES:
                if feat.lower() in ls.lower() and ":" in ls:
                    statuses.setdefault(feat, ls)

        # Cross-check expiry directly from license fields when present.
        expiry_lines = [
            ls for ls in out.splitlines()
            if any(k in ls.lower() for k in ("expir", "license"))
        ]
        expired_features: list[str] = []
        for feat in _REQUIRED_FEATURES:
            if feat in statuses:
                line = statuses[feat]
                # Heuristic: if the report mentions "Expir" near the feature, mark it
                if re.search(r"\bexpir(ed|y|ation)\b", line, re.I) and "valid" not in line.lower():
                    expired_features.append(feat)

        issues: list[str] = []
        if expired_features:
            issues.append(
                f"FortiGuard subscription expired/missing for: "
                f"{', '.join(sorted(expired_features))}"
            )

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:3072],
            evidence_stderr=err[:512],
            evidence_parsed={
                "feature_lines": statuses,
                "expiry_lines": expiry_lines[:8],
                "expired_features": sorted(expired_features),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _FortiGuardLicensesCheck()
register_check(CHECK)
