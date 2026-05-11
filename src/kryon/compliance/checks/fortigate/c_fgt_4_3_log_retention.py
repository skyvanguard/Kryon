"""FGT-4.3 — Log retention policy meets PCI-DSS 10.5.1 (>= 90 days online).

Local-only log storage is bounded by disk; PCI requires at least 90 days
of immediately-accessible logs. We inspect `config log disk setting` and
the `roll-time` / `maximum-log-age` knobs.

This is N/A on FortiGates without log-disk hardware (FortiGate-30E etc.);
those should rely on FortiAnalyzer (covered by FGT-4.1) — we surface N/A.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd

_MIN_RETENTION_DAYS = 90


class _LogRetentionCheck:
    control_id = "FGT-4.3"
    control_title = f"Log retention >= {_MIN_RETENTION_DAYS} days (PCI-DSS 10.5.1)"
    section = "4"
    severity = "MEDIUM"
    remediation_static = (
        "config log disk setting\n"
        "  set status enable\n"
        f"  set maximum-log-age {_MIN_RETENTION_DAYS}     # days online\n"
        "  set roll-schedule daily\n"
        "  set upload enable                              # offload to FTP/FAZ\n"
        "end\n"
        f"If hardware lacks a log disk, ensure FortiAnalyzer retention >= "
        f"{_MIN_RETENTION_DAYS} days (FGT-4.1 covers FAZ enablement)."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "show full-configuration log disk setting"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        # Some FortiGate models do not have a log disk → command returns
        # "Command fail" with rc != 0. Treat as N/A; FAZ retention is the
        # responsibility of FGT-4.1.
        if rc != 0 and ("not available" in out.lower() or "command fail" in out.lower()):
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="N/A",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={
                    "reason": "no local log disk on this hardware — see FGT-4.1 for FAZ",
                },
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )
        if rc != 0 and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not read log disk setting"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        status_m = re.search(r"^\s*set\s+status\s+(\S+)", out, re.M)
        max_age_m = re.search(r"^\s*set\s+maximum-log-age\s+(\d+)", out, re.M)

        status = status_m.group(1).lower() if status_m else "enable"
        max_age = int(max_age_m.group(1)) if max_age_m else 7  # FortiOS default

        issues: list[str] = []
        if status == "enable" and max_age < _MIN_RETENTION_DAYS:
            issues.append(
                f"maximum-log-age={max_age} < {_MIN_RETENTION_DAYS} days"
            )
        # If status is disable AND no FAZ → FGT-4.1 will catch it.

        verdict = "PASS" if not issues else "FAIL"
        return CheckResult(
            control_id=self.control_id,
            control_title=self.control_title,
            section=self.section,
            verdict=verdict,
            evidence_command=cmd,
            evidence_stdout=out[:1024],
            evidence_stderr=err[:512],
            evidence_parsed={
                "log_disk_status": status,
                "maximum_log_age_days": max_age,
                "minimum_required_days": _MIN_RETENTION_DAYS,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _LogRetentionCheck()
register_check(CHECK)
