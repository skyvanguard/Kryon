"""FGT-4.2 — Local log storage has memory headroom and is healthy.

`diagnose hardware sysinfo conserve` reports memory pressure; under
conserve mode FortiGate degrades log writes and signature updates. CIS
recommends keeping memory below conserve threshold via either FAZ
offload (no local logs) or sufficient RAM.
"""

from __future__ import annotations

import re
import time

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.runner import register_check, run_cmd


class _LogStorageCheck:
    control_id = "FGT-4.2"
    control_title = "FortiGate not in memory conserve mode (logs healthy)"
    section = "4"
    severity = "MEDIUM"
    remediation_static = (
        "If `Conserve mode is on`, take one of:\n"
        "  - Offload logs to FortiAnalyzer (config log fortianalyzer setting)\n"
        "  - Reduce log volume (config log memory filter / config log disk filter)\n"
        "  - Upgrade hardware (RAM is the most common bottleneck)\n"
        "Always confirm with `diagnose sys top-summary` to see top consumers."
    )

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        cmd = "diagnose hardware sysinfo conserve"
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
                evidence_parsed={"reason": "could not query conserve state"},
                remediation_static=self.remediation_static,
                severity=self.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        # FortiOS prints "Conserve mode: off" / "on"
        conserve_match = re.search(r"[Cc]onserve\s+mode\s*:\s*(\w+)", out)
        memory_used_match = re.search(r"memory used\s*:\s*(\d+)", out, re.I)
        memory_total_match = re.search(r"total memory\s*:\s*(\d+)", out, re.I)

        conserve = (conserve_match.group(1).lower() if conserve_match else "unknown")
        used = int(memory_used_match.group(1)) if memory_used_match else 0
        total = int(memory_total_match.group(1)) if memory_total_match else 0
        pct = round((used / total) * 100, 1) if total else 0.0

        issues: list[str] = []
        if conserve == "on":
            issues.append("Conserve mode is ON — log integrity at risk")
        if total > 0 and pct >= 90:
            issues.append(f"Memory usage {pct}% >= 90% threshold")

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
                "conserve_mode": conserve,
                "memory_used_kb": used,
                "memory_total_kb": total,
                "memory_used_pct": pct,
                "issues": sorted(issues),
            },
            remediation_static=self.remediation_static,
            severity=self.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


CHECK = _LogStorageCheck()
register_check(CHECK)
