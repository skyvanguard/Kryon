"""WIN-3.3 — Advanced Audit Policy enabled for security-relevant categories."""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.checks.windows._common import make_error, make_result
from kryon.compliance.runner import register_check, run_cmd

# Categories we expect Success+Failure auditing on (minimum CIS L1).
_REQUIRED_CATEGORIES = (
    "Logon/Logoff",
    "Account Logon",
    "Privilege Use",
    "Detailed Tracking",
    "Object Access",
)


class _AuditPolicyCheck:
    control_id = "WIN-3.3"
    control_title = "Advanced Audit Policy enabled for security-relevant categories"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Enable Success+Failure auditing for the high-value categories:\n"
        '  auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable\n'
        '  auditpol /set /category:"Account Logon" /success:enable /failure:enable\n'
        '  auditpol /set /category:"Privilege Use" /failure:enable\n'
        '  auditpol /set /category:"Detailed Tracking" /success:enable\n'
        "Enforce via GPO:\n"
        "  Computer Config → Windows Settings → Security Settings →\n"
        "    Advanced Audit Policy Configuration\n"
        "Also force the advanced audit policy override:\n"
        "  Local Policies → Security Options → Audit: Force audit policy\n"
        "    subcategory settings to override audit policy category settings: Enabled\n"
        "Without these, lateral movement and credential abuse leave no\n"
        "trace in the Windows event log."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "auditpol /get /category:*"
        out, err, rc = run_cmd(ctx, cmd, timeout_s=15)
        if rc != 0 and not out:
            return make_error(self, cmd=cmd, out=out, err=err, t0=t0, ctx=ctx, reason="auditpol call failed")

        missing: list[str] = []
        for category in _REQUIRED_CATEGORIES:
            # auditpol output looks like: "  Logon/Logoff           Success and Failure"
            # The category may be a header or a subcategory. We look for any
            # line matching the category name with success/failure.
            cat_in_text = category.lower() in out.lower()
            success_or_failure = category.lower() in out.lower() and (
                "success" in out.lower().split(category.lower(), 1)[-1][:200]
            )
            if not (cat_in_text and success_or_failure):
                missing.append(category)

        if missing:
            verdict, parsed = "FAIL", {"missing_categories": missing}
        else:
            verdict, parsed = "PASS", {"audited_categories": list(_REQUIRED_CATEGORIES)}
        return make_result(check=self, verdict=verdict, cmd=cmd, out=out, err=err, parsed=parsed, t0=t0, ctx=ctx)


CHECK = _AuditPolicyCheck()
register_check(CHECK)
