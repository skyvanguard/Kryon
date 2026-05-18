"""VOIP-3.2 — SIP-TLS configured for signalling.

Without TLS, SIP REGISTER + INVITE traffic crosses the network in
plaintext, including the Authorization header digest challenge and
extension-to-extension call setup. On-path observers can collect
hashes and brute-force them offline (eviltwin / wlan attacks).

Pass when either chan_sip `tlsenable=yes` or PJSIP transport with
`protocol=tls` is configured.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_TLS_MARKERS = (
    re.compile(r"^\s*tlsenable\s*=\s*yes\b", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*protocol\s*=\s*tls\b", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*tlsbindaddr\s*=", re.MULTILINE | re.IGNORECASE),
)


class _SipTlsDisabledCheck:
    control_id = "VOIP-3.2"
    control_title = "SIP-TLS configured for signalling"
    section = "3"
    severity = "MEDIUM"
    remediation_static = (
        "In /etc/asterisk/sip.conf (chan_sip):\n"
        "  tlsenable=yes\n"
        "  tlsbindaddr=0.0.0.0\n"
        "  tlscertfile=/etc/asterisk/certs/sip.pem\n"
        "Or in /etc/asterisk/pjsip.conf:\n"
        "  [transport-tls]\n"
        "    type=transport\n"
        "    protocol=tls\n"
        "    bind=0.0.0.0:5061\n"
        "    cert_file=/etc/asterisk/certs/sip.pem\n"
        "Combine with VOIP-3.1 (SRTP). Endpoint config must reference the\n"
        "TLS transport (`transport=transport-tls` per endpoint)."
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
        for rx in _TLS_MARKERS:
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
            evidence_parsed={"tls_markers_found": matched[:10]},
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


CHECK = _SipTlsDisabledCheck()
register_check(CHECK)
