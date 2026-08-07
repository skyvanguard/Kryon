"""VOIP-2.1 — `allowguest=no` enforced in sip.conf [general].

`allowguest=yes` (the upstream default) lets unauthenticated callers
land in the `[default]` dialplan context, which is the #1 vector for
toll-fraud abuse against unhardened Asterisk installs.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _AllowGuestCheck:
    control_id = "VOIP-2.1"
    control_title = "allowguest=no enforced in sip.conf [general]"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "In /etc/asterisk/sip.conf under `[general]`:\n"
        "  allowguest=no\n"
        "Then `asterisk -rx 'sip reload'` (or `pjsip reload` if using PJSIP).\n"
        "If using PJSIP, the equivalent is `endpoint` matching with explicit\n"
        "auth — no anonymous endpoint should exist."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/asterisk/sip.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        if rc != 0 and not out:
            return _err(self, cmd, out, err, t0, ctx, "could not read sip.conf")

        # Look at the [general] section only — guest setting elsewhere
        # doesn't affect the global behaviour.
        gen_match = re.search(r"^\[general\]\s*$(.*?)(?=^\[|\Z)", out, re.MULTILINE | re.DOTALL)
        if not gen_match:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="N/A",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:256],
                evidence_parsed={"reason": "no [general] section — likely PJSIP-only install"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        gen_body = gen_match.group(1)
        ag_match = re.search(r"^\s*allowguest\s*=\s*(\w+)", gen_body, re.MULTILINE | re.IGNORECASE)
        # Default is "yes" when not specified.
        allowguest_value = ag_match.group(1).lower() if ag_match else "yes (default)"
        verdict = "PASS" if allowguest_value == "no" else "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=gen_body[:1024],
            evidence_stderr=err[:256],
            evidence_parsed={"allowguest": allowguest_value},
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


def _err(check, cmd, out, err, t0, ctx, reason):
    return CheckResult(
        control_id=check.control_id,
        control_title=check.control_title,
        section=check.section,
        verdict="ERROR",
        evidence_command=cmd,
        evidence_stdout=out[:512],
        evidence_stderr=err[:512],
        evidence_parsed={"reason": reason},
        remediation_static=check.remediation_static,
        severity=check.severity,
        duration_ms=int((time.time() - t0) * 1000),
        host=ctx.host,
        run_id="",
    )


CHECK = _AllowGuestCheck()
register_check(CHECK)
