"""PCI-DSS v4 control 2.2.2 — Vendor default accounts.

Three sub-checks, verdict is FAIL if any fails:
  A) Empty-password shell accounts in /etc/shadow.
  B) MySQL root has empty password (if mysql-client available).
  C) SNMP responds to `public` community (if snmpwalk available).

Missing tools (mysql-client, snmpwalk) mark the corresponding sub-check
as N/A rather than failing — absence of the tool doesn't imply the
weakness is present.
"""

from __future__ import annotations

import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _check_empty_shadow(ctx: CheckContext) -> tuple[str, str, list[str]]:
    """Return (sub_verdict, raw_output, offending_accounts)."""
    stdout, stderr, rc = run_cmd(
        ctx,
        ["awk", "-F:", '($2==""||$2=="!"){print $1}', "/etc/shadow"],
        timeout_s=5,
    )
    if rc != 0:
        return "N/A", (stderr or stdout)[:512], []
    # "!" and "*" mean locked accounts, not empty; we filtered only "" above.
    # Some awk versions list !/! as locked — re-filter in Python to be safe.
    offenders = [line.strip() for line in stdout.splitlines() if line.strip() and not line.startswith("!")]
    return ("FAIL" if offenders else "PASS"), stdout, offenders


def _check_mysql_root(ctx: CheckContext) -> tuple[str, str, str]:
    which, _, rc = run_cmd(ctx, ["sh", "-c", "command -v mysql"], timeout_s=3)
    if rc != 0 or not which.strip():
        return "N/A", "mysql client not installed", ""
    stdout, stderr, rc = run_cmd(
        ctx,
        ["mysql", "-u", "root", "-e", "SELECT 1"],
        timeout_s=5,
    )
    if rc == 0:
        return "FAIL", stdout, "mysql root accepts empty password"
    return "PASS", stderr[:256], ""


def _check_snmp_public(ctx: CheckContext) -> tuple[str, str, str]:
    which, _, rc = run_cmd(ctx, ["sh", "-c", "command -v snmpwalk"], timeout_s=3)
    if rc != 0 or not which.strip():
        return "N/A", "snmpwalk not installed", ""
    stdout, stderr, rc = run_cmd(
        ctx,
        [
            "snmpwalk",
            "-v2c",
            "-c",
            "public",
            "-t",
            "3",
            "-r",
            "0",
            ctx.host if ctx.host != "localhost" else "127.0.0.1",
            "1.3.6.1.2.1.1.1.0",
        ],
        timeout_s=6,
    )
    if rc == 0 and stdout.strip():
        return "FAIL", stdout[:256], "SNMP community 'public' responds"
    return "PASS", (stderr or "no response to public")[:256], ""


class _C222Check:
    control_id = "2.2.2"
    control_title = "Vendor default accounts"
    section = "2"
    severity = "CRITICAL"
    remediation_static = (
        "Remove or lock any account with an empty password (`passwd -l <user>` "
        "or `usermod -L <user>`). Set a MySQL root password "
        "(`mysqladmin -u root password 'STRONG'`). Change SNMP community "
        "from `public` in /etc/snmp/snmpd.conf and reload the service."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        shadow_v, shadow_out, shadow_offenders = _check_empty_shadow(ctx)
        mysql_v, mysql_out, mysql_msg = _check_mysql_root(ctx)
        snmp_v, snmp_out, snmp_msg = _check_snmp_public(ctx)

        sub_verdicts = [shadow_v, mysql_v, snmp_v]
        if "FAIL" in sub_verdicts:
            verdict = "FAIL"
        elif all(v == "N/A" for v in sub_verdicts):
            verdict = "N/A"
        elif "ERROR" in sub_verdicts:
            verdict = "ERROR"
        else:
            verdict = "PASS"

        parsed = {
            "shadow_empty_password_accounts": sorted(shadow_offenders),
            "mysql_root_empty": mysql_msg or ("ok" if mysql_v == "PASS" else mysql_v),
            "snmp_public_responds": snmp_msg or ("ok" if snmp_v == "PASS" else snmp_v),
            "sub_verdicts": {
                "shadow": shadow_v,
                "mysql": mysql_v,
                "snmp": snmp_v,
            },
        }
        evidence_out = (f"=== shadow ===\n{shadow_out}\n=== mysql ===\n{mysql_out}\n=== snmp ===\n{snmp_out}")[:4096]

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="awk /etc/shadow ; mysql -u root -e 'SELECT 1' ; snmpwalk -c public",
            evidence_stdout=evidence_out,
            evidence_stderr="",
            evidence_parsed=parsed,
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C222Check()
register_check(CHECK)
