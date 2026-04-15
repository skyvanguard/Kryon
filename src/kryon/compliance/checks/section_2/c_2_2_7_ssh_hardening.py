"""PCI-DSS v4 control 2.2.7 — Non-console administrative access encryption.

Enforces SSH hardening minimums:
  - PermitRootLogin: must be `no` or `prohibit-password`.
  - Protocol: must be 2 (OpenSSH 7.x+ hardcodes this; we check explicit config).
  - MaxAuthTries: must be <= 4.
  - Ciphers: CBC ciphers (aes128-cbc, aes192-cbc, aes256-cbc, 3des-cbc) must be absent.

Evidence: `sshd -T | grep -iE 'permitrootlogin|protocol|maxauthtries|ciphers'`.
Falls back to `/etc/ssh/sshd_config` parse if `sshd -T` unavailable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


_WEAK_CIPHERS = {"aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc", "blowfish-cbc"}


def _parse_sshd_t(output: str) -> dict:
    parsed: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            parsed[parts[0].lower()] = parts[1].strip()
    return parsed


class _C227Check:
    control_id = "2.2.7"
    control_title = "Non-console administrative access encryption"
    section = "2"
    severity = "HIGH"
    remediation_static = (
        "Edit /etc/ssh/sshd_config: set `PermitRootLogin no`, "
        "`MaxAuthTries 4`, and restrict `Ciphers` to modern AEAD suites "
        "(chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com). "
        "Reload: `systemctl reload sshd`."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        stdout, stderr, rc = run_cmd(ctx, ["sshd", "-T"], timeout_s=8)

        if rc != 0 or not stdout.strip():
            # Fallback: parse sshd_config directly
            sc_out, sc_err, sc_rc = run_cmd(
                ctx, ["cat", "/etc/ssh/sshd_config"], timeout_s=5
            )
            if sc_rc != 0:
                return CheckResult(
                    control_id=self.control_id,
                    control_title=self.control_title,
                    section=self.section,
                    verdict="ERROR",
                    evidence_command="sshd -T || cat /etc/ssh/sshd_config",
                    evidence_stdout=stdout,
                    evidence_stderr=(stderr + "\n" + sc_err)[:1024],
                    evidence_parsed={},
                    remediation_static=self.remediation_static,
                    severity=self.severity,
                    duration_ms=int((time.time() - t0) * 1000),
                    host=ctx.host,
                    run_id="",
                )
            stdout = sc_out
            evidence_command = "cat /etc/ssh/sshd_config"
        else:
            evidence_command = "sshd -T"

        parsed = _parse_sshd_t(stdout)
        issues: list[str] = []

        permit = parsed.get("permitrootlogin", "").lower()
        if permit and permit not in ("no", "prohibit-password"):
            issues.append(f"PermitRootLogin={permit}")

        max_auth = parsed.get("maxauthtries", "")
        try:
            if max_auth and int(max_auth) > 4:
                issues.append(f"MaxAuthTries={max_auth}")
        except ValueError:
            issues.append(f"MaxAuthTries unparseable: {max_auth!r}")

        protocol = parsed.get("protocol", "")
        if protocol and protocol != "2":
            issues.append(f"Protocol={protocol}")

        ciphers_raw = parsed.get("ciphers", "")
        if ciphers_raw:
            offered = {c.strip().lower() for c in ciphers_raw.split(",")}
            weak = offered & _WEAK_CIPHERS
            if weak:
                issues.append(f"weak_ciphers={sorted(weak)}")

        verdict = "PASS" if not issues else "FAIL"
        parsed_ev = {
            "permit_root_login": permit,
            "max_auth_tries": max_auth,
            "protocol": protocol,
            "ciphers_present_weak": sorted(list(
                {c.strip().lower() for c in ciphers_raw.split(",")} & _WEAK_CIPHERS
            )) if ciphers_raw else [],
            "issues": sorted(issues),
        }

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=evidence_command,
            evidence_stdout=stdout[:4096],
            evidence_stderr=stderr[:1024],
            evidence_parsed=parsed_ev,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C227Check()
register_check(CHECK)
