"""VOIP-1.2 — AMI not using a default / weak secret.

Asterisk Manager Interface (`/etc/asterisk/manager.conf`) is the
remote-control API. Default installs ship with example credentials
that many sites never rotate. Common defaults seen in the wild:
  - `mysecret` (literal example value in the upstream sample)
  - `amp111` (FreePBX default)
  - `manager` (matches username)
  - `secret`, `1234`, empty, `admin`
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_KNOWN_DEFAULT_SECRETS = {
    "",
    "mysecret",
    "amp111",
    "manager",
    "secret",
    "admin",
    "1234",
    "12345",
    "password",
    "asterisk",
}

_AMI_USER_BLOCK_RE = re.compile(
    r"^\[(?!general\]|\s)([^\]]+)\]\s*$(.*?)(?=^\[|\Z)",
    re.MULTILINE | re.DOTALL,
)


class _AmiDefaultSecretCheck:
    control_id = "VOIP-1.2"
    control_title = "AMI not using a default / weak secret"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "Rotate every AMI user secret in /etc/asterisk/manager.conf:\n"
        "  [admin]\n"
        "    secret = <14+ char random passphrase>\n"
        "    permit = 127.0.0.1/255.255.255.255\n"
        "    deny  = 0.0.0.0/0.0.0.0\n"
        "Then reload Asterisk: `asterisk -rx 'manager reload'`.\n"
        "Bind AMI to localhost only (`bindaddr=127.0.0.1` in `[general]`)\n"
        "unless an external service truly needs it, in which case lock\n"
        "down via `permit`/`deny` ACL + TLS (`tlsbindaddr`)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/asterisk/manager.conf 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        if rc != 0 and not out:
            return _err(self, cmd, out, err, t0, ctx, "could not read manager.conf")

        weak_users: list[dict[str, str]] = []
        for m in _AMI_USER_BLOCK_RE.finditer(out):
            user = m.group(1).strip()
            body = m.group(2)
            secret_match = re.search(r"^\s*secret\s*=\s*(.*?)\s*$", body, re.MULTILINE)
            if not secret_match:
                continue
            secret = secret_match.group(1).strip()
            if secret.lower() in _KNOWN_DEFAULT_SECRETS or len(secret) < 8:
                weak_users.append({"user": user, "secret_length": str(len(secret))})

        verdict = "FAIL" if weak_users else "PASS"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:1024],
            evidence_stderr=err[:256],
            evidence_parsed={"weak_users": weak_users},
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


CHECK = _AmiDefaultSecretCheck()
register_check(CHECK)
