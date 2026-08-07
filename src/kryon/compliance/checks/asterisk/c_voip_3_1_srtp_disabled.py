"""VOIP-3.1 — SRTP (encrypted RTP) configured for at least one endpoint.

Plain RTP traffic is unencrypted by default. Anyone on the call path
(switches, routers, MITM on the LAN) can replay audio packets. SRTP
(RFC 3711) encrypts the media stream. This check looks at sip.conf
and pjsip.conf for `media_encryption=sdes` / `encryption=yes` /
`srtpcapable=yes` directives.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_SRTP_MARKERS = (
    re.compile(r"^\s*media_encryption\s*=\s*(sdes|dtls)\b", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*encryption\s*=\s*yes\b", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*srtpcapable\s*=\s*yes\b", re.MULTILINE | re.IGNORECASE),
)


class _SrtpDisabledCheck:
    control_id = "VOIP-3.1"
    control_title = "SRTP (encrypted RTP) configured for at least one endpoint"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "Enable SRTP per endpoint in /etc/asterisk/pjsip.conf:\n"
        "  [<endpoint>]\n"
        "    type=endpoint\n"
        "    media_encryption=sdes        ; or 'dtls' if certs available\n"
        "    transport=transport-tls\n"
        "Or for chan_sip in /etc/asterisk/sip.conf:\n"
        "  encryption=yes\n"
        "Combine with VOIP-3.2 (SIP-TLS on signalling). Plain RTP is OK\n"
        "for fully-isolated VLANs but discouraged in branch-to-HQ flows."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "echo '--sip.conf--'; cat /etc/asterisk/sip.conf 2>/dev/null; "
            "echo '--pjsip.conf--'; cat /etc/asterisk/pjsip.conf 2>/dev/null"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)

        if rc != 0 and not out:
            return _err(self, cmd, out, err, t0, ctx, "could not read sip/pjsip configs")

        matched: list[str] = []
        for rx in _SRTP_MARKERS:
            for m in rx.finditer(out):
                matched.append(m.group(0).strip())

        verdict = "PASS" if matched else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:1024],
            evidence_stderr=err[:256],
            evidence_parsed={"srtp_markers_found": matched[:10]},
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


CHECK = _SrtpDisabledCheck()
register_check(CHECK)
