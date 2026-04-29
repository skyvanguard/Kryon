"""FGT-1.1 — No admin account with empty / vendor-default password.

FortiGate ships with `admin` account having no password by default. Many
deployments never rotate it. We list admin accounts via `show system admin`
and flag any that:
  - Are still named exactly `admin` AND have no `set password` directive
    (means default empty password — login is just `admin` + Enter).
  - Have `set password ENC` followed by a known-default hash (rare; FortiOS
    salts unique per-install, so this is best-effort string match).

Detection is conservative: we PASS by default and only FAIL when we have
positive evidence. ERROR if the SSH transport returns nothing usable.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


# Known vendor-default password hashes seen on freshly imaged FGT VMs.
# FortiOS uses unique salts so this match rarely triggers in practice; we
# keep it as a sanity layer alongside the empty-password detection.
_KNOWN_DEFAULT_HASHES = (
    "AK1",  # FortiOS empty-password marker prefix in some versions
)


class _DefaultCredsCheck:
    control_id = "FGT-1.1"
    control_title = "No admin account with empty / vendor-default password"
    section = "1"
    severity = "CRITICAL"
    remediation_static = (
        "Set a strong password for every admin account:\n"
        "  config system admin\n"
        "    edit admin\n"
        "      set password <STRONG_PASSPHRASE>\n"
        "    next\n"
        "  end\n"
        "Then enable a password policy:\n"
        "  config system password-policy\n"
        "    set status enable\n"
        "    set minimum-length 14\n"
        "    set min-lower-case-letter 1\n"
        "    set min-upper-case-letter 1\n"
        "    set min-non-alphanumeric 1\n"
        "    set min-number 1\n"
        "  end\n"
        "Rotate `admin` to a non-default username and create per-operator accounts."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show system admin"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=10)

        if rc != 0 and not out:
            return _error(self, cmd, out, err, t0, ctx, "could not read admin config")

        # Parse out per-account blocks: `edit "name" ... next`
        accounts: list[dict[str, str]] = []
        for m in re.finditer(
            r'edit\s+"([^"]+)"\s*(.*?)\bnext\b',
            out,
            re.S,
        ):
            name = m.group(1)
            body = m.group(2)
            password_line = ""
            for line in body.splitlines():
                ls = line.strip()
                if ls.startswith("set password"):
                    password_line = ls
                    break
            accounts.append({"name": name, "password_line": password_line})

        issues: list[str] = []
        for acct in accounts:
            if not acct["password_line"]:
                issues.append(
                    f"admin '{acct['name']}' has no `set password` directive "
                    "(possible empty / vendor-default password)"
                )
                continue
            for marker in _KNOWN_DEFAULT_HASHES:
                if marker in acct["password_line"] and len(acct["password_line"]) < 30:
                    issues.append(
                        f"admin '{acct['name']}' uses suspected default-password marker"
                    )
                    break

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:2048],
            evidence_stderr=err[:512],
            evidence_parsed={
                "admin_count": len(accounts),
                "admin_names": sorted(a["name"] for a in accounts),
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


def _error(check, cmd: str, out: str, err: str, t0: float, ctx: CheckContext, reason: str) -> CheckResult:
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


CHECK = _DefaultCredsCheck()
register_check(CHECK)
