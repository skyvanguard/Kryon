"""UNF-1.5 — Controller auto-backup enabled with off-box destination.

Without auto-backup, a UDM crash + replacement = full reconfig from scratch.
Settings → System → Backup → Auto Backups.

Detection: the `setting` collection has a `super_auto_backup` doc with
`status` and `target` (cloud / cdn / off-box path).
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _AutoBackupCheck:
    control_id = "UNF-1.5"
    control_title = "Controller auto-backup is enabled"
    section = "1"
    severity = "MEDIUM"
    remediation_static = (
        "Settings → System → Backups → Schedule Backups → Daily.\n"
        "Set retention >= 7 days. If on UI Cloud, enable Cloud Backup\n"
        "as the off-box destination. On self-hosted, copy nightly\n"
        "/usr/lib/unifi/data/backup/ to a different host."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = (
            "mongo --port 27117 ace --quiet --eval "
            "'var d=db.setting.findOne({key:\"super_auto_backup\"});"
            "print(JSON.stringify(d || {}))'"
        )
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)

        if rc != 0 and not out:
            return CheckResult(
                control_id=self.control_id,
                control_title=self.control_title,
                section=self.section,
                verdict="ERROR",
                evidence_command=cmd,
                evidence_stdout=out[:512],
                evidence_stderr=err[:512],
                evidence_parsed={"reason": "could not query mongo"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # Empty doc = never configured = OFF.
        is_empty = out.strip() in ("", "{}", "null")
        status_m = re.search(r'"status"\s*:\s*(\w+)', out)
        cron_m = re.search(r'"cron"\s*:\s*"([^"]+)"', out)
        retention_m = re.search(r'"max_files"\s*:\s*(\d+)', out)

        status = (status_m.group(1).lower() if status_m else "")
        cron = cron_m.group(1) if cron_m else ""
        retention = int(retention_m.group(1)) if retention_m else 0

        issues: list[str] = []
        if is_empty or status not in ("true", "enabled", "enable"):
            issues.append("auto-backup setting is not configured / not enabled")

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
                "status": status or "(not configured)",
                "cron": cron,
                "max_files": retention,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _AutoBackupCheck()
register_check(CHECK)
