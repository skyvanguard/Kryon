"""PVE-8.1 — Scheduled backup jobs are configured.

A hypervisor with no backup schedule risks total VM/CT data loss on a
storage or node failure. Proxmox keeps scheduled backup (vzdump) jobs in
/etc/pve/jobs.cfg (modern) and legacy /etc/pve/vzdump.cron.

FAIL if no vzdump backup job is defined. ERROR if the config can't be read.
(This checks that a schedule EXISTS; verifying it actually runs / restores
is a manual evidence step.)
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _BackupJobsCheck:
    control_id = "PVE-8.1"
    control_title = "Scheduled backup jobs configured (vzdump)"
    section = "8"
    severity = "HIGH"
    remediation_static = (
        "Define a scheduled backup job (Datacenter → Backup) or on the CLI:\n"
        "  pvesh create /cluster/backup --schedule '02:00' --storage <pbs-or-nfs> \\\n"
        "    --mode snapshot --all 1 --compress zstd\n"
        "Prefer Proxmox Backup Server (dedup + verify). Test restores periodically."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "cat /etc/pve/jobs.cfg /etc/pve/vzdump.cron 2>/dev/null"
        out, err, rc = run_cmd(ctx, cmd, shell=True, timeout_s=8)
        if rc != 0 and not out.strip():
            return self._result("ERROR", cmd, out, err, {"reason": "could not read backup job config"}, t0, ctx)

        # jobs.cfg: "vzdump: <id>" blocks; vzdump.cron: lines containing "vzdump".
        job_ids = re.findall(r"^\s*vzdump:\s*(\S+)", out, re.M)
        cron_jobs = [ln for ln in out.splitlines() if "vzdump" in ln and not ln.strip().startswith("#")]
        has_backup = bool(job_ids) or bool(cron_jobs)

        verdict = "PASS" if has_backup else "FAIL"
        return self._result(
            verdict,
            cmd,
            out,
            err,
            {"vzdump_job_ids": job_ids, "cron_backup_lines": len(cron_jobs), "has_backup": has_backup},
            t0,
            ctx,
        )

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


CHECK = _BackupJobsCheck()
register_check(CHECK)
