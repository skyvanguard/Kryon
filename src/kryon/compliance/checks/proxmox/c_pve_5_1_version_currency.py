"""PVE-5.1 — Proxmox version is supported and patches are current.

We check two things:
  1. `pveversion` reports a release inside the supported window (PVE 7.x
     had EOL 2024-07; PVE 8.x is supported through ~2026-07).
  2. `apt-get -s upgrade` dry-run returns 0 pending security updates —
     if > 0, we flag as FAIL with the number.

This is a standard quarterly finding — banks patch on a fixed cadence
and auditors want evidence of currency.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


# Minimum major.minor that is still vendor-supported as of bench date.
SUPPORTED_MIN = (8, 0)
EOL_MAJOR = {7: "2024-07", 6: "2022-07"}


class _VersionCurrencyCheck:
    control_id = "PVE-5.1"
    control_title = "Proxmox version is supported and security patches applied"
    section = "5"
    severity = "MEDIUM"
    remediation_static = (
        "Run `apt update && apt dist-upgrade -y` on a maintenance window. "
        "Major upgrades: follow official PVE 7→8 guide. "
        "Enable the no-subscription repo only for dev; "
        "prod banking must use pve-enterprise repo with support contract."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        ver_cmd = "pveversion --verbose 2>&1 | head -5"
        apt_cmd = (
            "apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null "
            "| grep -c '^Inst ' || echo 0"
        )
        v_out, v_err, v_rc = run_cmd(ctx, ver_cmd, shell=True, timeout_s=8)
        a_out, a_err, _ = run_cmd(ctx, apt_cmd, shell=True, timeout_s=30)

        if v_rc != 0 or not v_out.strip():
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=f"{ver_cmd} ; {apt_cmd}",
                evidence_stdout=v_out[:512],
                evidence_stderr=v_err[:512],
                evidence_parsed={"reason": "pveversion failed (not a Proxmox node?)"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # Expect first line: pve-manager/8.2.4/... or proxmox-ve: 8.2.0 (running kernel: ...)
        m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", v_out)
        major = int(m.group(1)) if m else 0
        minor = int(m.group(2)) if m else 0
        patch = int(m.group(3)) if m and m.group(3) else 0

        try:
            pending = int(a_out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            pending = -1

        issues: list[str] = []
        if major < SUPPORTED_MIN[0]:
            eol = EOL_MAJOR.get(major, "unknown")
            issues.append(f"Proxmox {major}.{minor} is EOL (support ended {eol})")
        elif (major, minor) < SUPPORTED_MIN:
            issues.append(f"Proxmox {major}.{minor} below minimum supported {SUPPORTED_MIN[0]}.{SUPPORTED_MIN[1]}")
        if pending > 0:
            issues.append(f"{pending} package upgrades pending")
        if pending == -1:
            issues.append("Could not query pending upgrades (apt simulation failed)")

        verdict = "PASS" if not issues else "FAIL"

        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=f"{ver_cmd} ; {apt_cmd}",
            evidence_stdout=f"=== pveversion ===\n{v_out}\n=== pending upgrades ===\n{pending}"[:1024],
            evidence_stderr=(v_err + "\n" + a_err)[:512],
            evidence_parsed={
                "version": f"{major}.{minor}.{patch}",
                "pending_upgrades": pending,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _VersionCurrencyCheck()
register_check(CHECK)
