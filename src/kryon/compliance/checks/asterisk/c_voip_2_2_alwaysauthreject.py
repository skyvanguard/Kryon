"""VOIP-2.2 — `alwaysauthreject=yes` enforced in sip.conf [general].

When set to `no`, Asterisk responds differently to authentication
attempts against existing vs nonexistent users — `403 Forbidden` vs
`404 Not Found`. Attackers use this side-channel to enumerate valid
SIP usernames before brute-forcing passwords. `alwaysauthreject=yes`
collapses both into the same 401 challenge, killing the enumeration
path.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _AlwaysAuthRejectCheck:
    control_id = "VOIP-2.2"
    control_title = "alwaysauthreject=yes enforced in sip.conf [general]"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "In /etc/asterisk/sip.conf under `[general]`:\n"
        "  alwaysauthreject=yes\n"
        "Then `asterisk -rx 'sip reload'`.\n"
        "This is the default from Asterisk 11+ but many sites carried over\n"
        "older configs where it was `no`. PJSIP is not affected (its auth\n"
        "model already enforces this behaviour)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/asterisk/sip.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        if rc != 0 and not out:
            return _err(self, cmd, out, err, t0, ctx, "could not read sip.conf")

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
                evidence_parsed={"reason": "no [general] section — likely PJSIP-only"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        gen_body = gen_match.group(1)
        m = re.search(r"^\s*alwaysauthreject\s*=\s*(\w+)", gen_body, re.MULTILINE | re.IGNORECASE)
        # Default since Asterisk 11 is "yes".
        explicit = m.group(1).lower() if m else ""
        value = explicit or "yes (default in modern asterisk)"
        verdict = "PASS" if (not explicit or explicit == "yes") else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=gen_body[:1024],
            evidence_stderr=err[:256],
            evidence_parsed={"alwaysauthreject": value},
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


CHECK = _AlwaysAuthRejectCheck()
register_check(CHECK)
