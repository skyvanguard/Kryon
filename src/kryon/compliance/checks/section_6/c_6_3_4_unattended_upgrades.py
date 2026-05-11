"""CIS section 6 control 6.3.4 — Automatic security updates.

A Debian/Ubuntu host must have automatic security-patch installation
configured so kernel and library CVEs land without manual intervention.

Two conditions required:
  - Package `unattended-upgrades` is installed.
  - `/etc/apt/apt.conf.d/20auto-upgrades` enables the periodic updater
    (APT::Periodic::Unattended-Upgrade "1").

Evidence: `dpkg -l unattended-upgrades` + `cat /etc/apt/apt.conf.d/20auto-upgrades`.
Verdict FAIL when either is missing.

Closes ground-truth gap H-02.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_PKG_OK_RE = re.compile(r"^ii\s+unattended-upgrades\s", re.MULTILINE)
_PERIODIC_RE = re.compile(
    r'APT::Periodic::Unattended-Upgrade\s+"1"',
    re.IGNORECASE,
)


class _C634Check:
    control_id = "6.3.4"
    control_title = "Unattended security upgrades configured"
    section = "6"
    severity = "HIGH"
    remediation_static = (
        "apt-get install -y unattended-upgrades && "
        "dpkg-reconfigure -plow unattended-upgrades. Verify /etc/apt/apt."
        'conf.d/20auto-upgrades has APT::Periodic::Unattended-Upgrade "1".'
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        pkg_out, pkg_err, _ = run_cmd(
            ctx,
            ["dpkg", "-l", "unattended-upgrades"],
            timeout_s=5,
        )
        cfg_out, cfg_err, cfg_rc = run_cmd(
            ctx,
            ["cat", "/etc/apt/apt.conf.d/20auto-upgrades"],
            timeout_s=5,
        )

        pkg_installed = bool(_PKG_OK_RE.search(pkg_out or ""))
        periodic_on = bool(_PERIODIC_RE.search(cfg_out or "")) if cfg_rc == 0 else False

        issues: list[str] = []
        if not pkg_installed:
            issues.append("unattended-upgrades package not installed")
        if not periodic_on:
            issues.append('APT::Periodic::Unattended-Upgrade != "1" in 20auto-upgrades')

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=("dpkg -l unattended-upgrades; cat /etc/apt/apt.conf.d/20auto-upgrades"),
            evidence_stdout=(pkg_out + "\n---\n" + cfg_out)[:4096],
            evidence_stderr=(pkg_err + "\n" + cfg_err)[:1024],
            evidence_parsed={
                "package_installed": pkg_installed,
                "periodic_unattended_upgrade": periodic_on,
                "issues": issues,
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _C634Check()
register_check(CHECK)
