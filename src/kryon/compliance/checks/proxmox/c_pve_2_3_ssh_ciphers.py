"""PVE-2.3 — SSH uses strong ciphers / KEX / MACs.

Key-based auth (2.1) is undermined if the SSH transport still negotiates
weak algorithms: CBC-mode ciphers, arcfour, 3des, hmac-md5/sha1, or the
diffie-hellman-group1/group14-sha1 key exchange. Checks the EFFECTIVE sshd
config via `sshd -T`.

FAIL if any weak cipher/KEX/MAC is offered. ERROR if sshd config can't be read.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

# Substrings that flag a weak algorithm in ciphers/kex/macs lists.
_WEAK = (
    "-cbc",
    "arcfour",
    "3des",
    "hmac-md5",
    "hmac-sha1",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
)


class _SshCiphersCheck:
    control_id = "PVE-2.3"
    control_title = "SSH uses strong ciphers/KEX/MACs (no weak algorithms)"
    section = "2"
    severity = "MEDIUM"
    remediation_static = (
        "Restrict SSH crypto in /etc/ssh/sshd_config (or a drop-in):\n"
        "  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr\n"
        "  KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512\n"
        "  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\n"
        "Then `systemctl restart sshd`."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "sshd -T 2>/dev/null | grep -iE '^(ciphers|kexalgorithms|macs) '"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read effective sshd config"}, t0, ctx)

        low = out.lower()
        weak_found = sorted({w for w in _WEAK if w in low})
        verdict = "FAIL" if weak_found else "PASS"
        return self._result(verdict, cmd, out, err, {"weak_algorithms": weak_found}, t0, ctx)

    def _result(self, verdict, cmd, out, err, parsed, t0, ctx) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:2048],
            evidence_stderr=err[:512],
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _SshCiphersCheck()
register_check(CHECK)
