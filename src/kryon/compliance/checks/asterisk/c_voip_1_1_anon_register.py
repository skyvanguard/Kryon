"""VOIP-1.1 — No anonymous SIP REGISTER permitted on `[default]` context.

Asterisk's `[default]` context is what unauthenticated callers land in
when `sip.conf` has `allowguest=yes` (covered by VOIP-2.1) OR when the
dialplan exposes the `[default]` context with extensions that initiate
calls. This check looks at `extensions.conf` for the `[default]`
context: if it contains `Dial(` or `Goto(` to non-trivial extensions,
unauthenticated callers can place arbitrary calls (toll fraud).

PASS when `[default]` is empty / has only `Playback`/`Hangup` / does
not call out. FAIL when `[default]` contains a Dial/Goto exposing
non-trivial routing.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_DEFAULT_CTX_RE = re.compile(r"^\[default\]\s*$.*?(?=^\[|\Z)", re.MULTILINE | re.DOTALL)
_DANGEROUS_APP_RE = re.compile(r"\b(Dial|Goto|Macro|Set\([^)]*PJSIP|System|Exec)\(", re.IGNORECASE)


class _AnonRegisterCheck:
    control_id = "VOIP-1.1"
    control_title = "No anonymous SIP REGISTER permitted on [default] context"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "Restrict the `[default]` context in /etc/asterisk/extensions.conf:\n"
        "  [default]\n"
        "    exten => _X.,1,Hangup()\n"
        "Move all dialing logic to authenticated contexts (e.g. `[from-internal]`)\n"
        "reachable only after SIP authentication. Combine with VOIP-2.1\n"
        "(allowguest=no) and VOIP-2.2 (alwaysauthreject=yes)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/asterisk/extensions.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        if rc != 0 and not out:
            return _err(self, cmd, out, err, t0, ctx, "could not read extensions.conf")

        m = _DEFAULT_CTX_RE.search(out)
        if not m:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="PASS",
                evidence_command=cmd,
                evidence_stdout=out[:1024],
                evidence_stderr=err[:256],
                evidence_parsed={"default_context_found": False},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        default_body = m.group(0)
        dangerous = _DANGEROUS_APP_RE.findall(default_body)
        verdict = "FAIL" if dangerous else "PASS"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=default_body[:1024],
            evidence_stderr=err[:256],
            evidence_parsed={
                "default_context_found": True,
                "dangerous_apps": sorted(set(dangerous)),
            },
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


CHECK = _AnonRegisterCheck()
register_check(CHECK)
