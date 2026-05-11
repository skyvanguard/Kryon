"""PCI-DSS v4 control 6.3.3 — Critical security patches within 30 days.

Verdict logic (Debian/Ubuntu — the primary target family for bank servers):
  FAIL if: pending security updates present, OR last security update > 30 days old.
  PASS if: no pending security updates AND last security update <= 30 days old.
  N/A if: non-apt system (CentOS/RHEL family out of scope this sprint; handled in F15.2).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


def _count_security_upgradable(output: str) -> int:
    """Parse `apt list --upgradable` output, count lines mentioning -security."""
    count = 0
    for line in output.splitlines():
        if "/" not in line:
            continue
        # heuristic: Ubuntu security updates carry '-security' in the channel name
        if "-security" in line:
            count += 1
    return count


def _parse_last_upgrade_days(dpkg_log_output: str) -> int | None:
    """Extract most recent 'upgrade' action from dpkg.log, compute age in days.

    Input: `grep -h ' upgrade ' /var/log/dpkg.log*`-style output (head lines: 'YYYY-MM-DD HH:MM:SS upgrade pkg ...')
    """
    from datetime import datetime
    latest: datetime | None = None
    for line in dpkg_log_output.splitlines():
        m = re.match(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) upgrade ", line)
        if not m:
            continue
        try:
            ts = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if latest is None or ts > latest:
            latest = ts
    if latest is None:
        return None
    # Age relative to "now" — but in a deterministic audit we prefer the system's
    # own clock as read by the target. We compare here on audit host time;
    # reproducibility handled by stripping duration_ms upstream, not by date.
    age = (datetime.now() - latest).days
    return age


class _C633Check:
    control_id = "6.3.3"
    control_title = "Critical security patches within 30 days"
    section = "6"
    severity = "HIGH"
    remediation_static = (
        "Enable unattended security upgrades: `apt install unattended-upgrades`. "
        "Apply pending updates immediately: `apt update && apt upgrade -y`. "
        "Configure automatic reboots for kernel/libc patches where appropriate "
        "(see /etc/apt/apt.conf.d/50unattended-upgrades)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()

        # Detect apt availability
        which_apt, _, rc_which = run_cmd(ctx, ["sh", "-c", "command -v apt"], timeout_s=3)
        if rc_which != 0 or not which_apt.strip():
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="N/A",
                evidence_command="command -v apt",
                evidence_stdout=which_apt,
                evidence_stderr="non-apt system; out of scope in F15.1",
                evidence_parsed={"system": "non-apt"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        upg_out, upg_err, rc_upg = run_cmd(
            ctx, ["sh", "-c", "apt list --upgradable 2>/dev/null"], timeout_s=20,
        )
        sec_count = _count_security_upgradable(upg_out)

        dpkg_out, _, _ = run_cmd(
            ctx, ["sh", "-c",
                  "grep -h ' upgrade ' /var/log/dpkg.log* 2>/dev/null | tail -500"],
            timeout_s=5,
        )
        age_days = _parse_last_upgrade_days(dpkg_out)

        # Verdict
        if sec_count > 0:
            verdict = "FAIL"
            reason = f"{sec_count} security update(s) pending"
        elif age_days is None:
            verdict = "FAIL"
            reason = "no upgrade history found in /var/log/dpkg.log*"
        elif age_days > 30:
            verdict = "FAIL"
            reason = f"last upgrade {age_days} days ago (> 30)"
        else:
            verdict = "PASS"
            reason = f"no pending security updates; last upgrade {age_days} days ago"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command="apt list --upgradable ; grep 'upgrade' /var/log/dpkg.log*",
            evidence_stdout=upg_out[:2048] + "\n\n--- dpkg.log tail ---\n" + dpkg_out[:2048],
            evidence_stderr=upg_err[:512],
            evidence_parsed={
                "security_updates_pending": sec_count,
                "last_upgrade_age_days": age_days,
                "reason": reason,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C633Check()
register_check(CHECK)
